package reputation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// malantaHost is the built-in, non-removable allowed host for the Malanta
// provider (see config.validateAPIBaseURL — the env-additive allowlist can
// only append to this, never subtract it).
const malantaHost = "app.malanta.ai"

// malantaBatchSize is the default per-request batch size, and Malanta's
// documented hard per-request LIMIT for both /v1/domains/reputation and
// /v1/ips/reputation (1-100 deduped entries; >100 returns HTTP 400).
// Overridable down to any smaller value via config.Config.APIBatchSize /
// MALANTA_API_BATCH_SIZE (see WithMalantaBatchSize) — config.Load's
// validateBatchSize enforces the 1-100 ceiling at config time.
const malantaBatchSize = 100

// MalantaProvider implements Provider against Malanta's
// getDomainLabelByDomains-successor batch reputation API
// (POST /v1/domains/reputation, POST /v1/ips/reputation,
// POST /v1/code-repos/reputation).
//
// CONSTRAINT: both the batch and single Malanta domain endpoints accept
// only REGISTERED domains (eTLD+1) — a subdomain returns HTTP 422. This
// provider therefore always reduces a domain Indicator to its registrable
// form (golang.org/x/net/publicsuffix.EffectiveTLDPlusOne) before querying,
// and fans the single registered-domain verdict back onto every original
// Indicator that reduced to it. Consequence: Malanta domain reputation is
// registered-domain granularity only — a malicious subdomain on an
// otherwise-clean registered domain is evaluated at the eTLD+1 level. IPv4
// and GitHub repo/owner indicators are queried as-is (no reduction — the
// reduction is a hostname operation and would corrupt any other Kind).
type MalantaProvider struct {
	baseURL string
	apiKey  string
	http    *http.Client

	batchSize      int
	maxConcurrency int
	attemptTimeout time.Duration
	maxAttempts    int
}

// MalantaOption configures a MalantaProvider.
type MalantaOption func(*MalantaProvider)

// WithMalantaRetry enables transient-error retry per HTTP attempt. See
// reputation.errTransient: only transport-level failures are retried, never
// an HTTP status or a decode error, so a genuine malicious verdict (or an
// HTTP 429) is never softened by a retry.
func WithMalantaRetry(attemptTimeout time.Duration, maxAttempts int) MalantaOption {
	return func(p *MalantaProvider) {
		p.attemptTimeout = attemptTimeout
		if maxAttempts >= 1 {
			p.maxAttempts = maxAttempts
		}
	}
}

// WithMalantaConcurrency bounds how many batch chunks (each up to
// batchSize indicators) are in flight at once. Only matters when a single
// event's fan-out exceeds one chunk; keeps a large legitimate event's
// total latency close to one request's latency rather than N times it.
func WithMalantaConcurrency(n int) MalantaOption {
	return func(p *MalantaProvider) {
		if n >= 1 {
			p.maxConcurrency = n
		}
	}
}

// WithMalantaBatchSize overrides how many domains/IPs are sent per
// request, in place of the malantaBatchSize default. n must be 1-100 —
// config.Load's validateBatchSize is expected to have already rejected an
// out-of-range value from config.json/env before this ever runs, but this
// constructor-level guard means an out-of-range n here is a silent no-op
// (falls back to the built-in default) rather than producing chunks the
// API will 400 on — belt and suspenders.
func WithMalantaBatchSize(n int) MalantaOption {
	return func(p *MalantaProvider) {
		if n >= 1 && n <= 100 {
			p.batchSize = n
		}
	}
}

// NewMalanta returns a Malanta Provider. baseURL and apiKey are assumed
// already validated by config.Load (validateAPIBaseURL enforces https +
// the host allowlist before this constructor ever runs).
func NewMalanta(baseURL, apiKey string, opts ...MalantaOption) *MalantaProvider {
	p := &MalantaProvider{
		baseURL: baseURL,
		apiKey:  apiKey,
		http: &http.Client{
			CheckRedirect: blockCrossHostRedirect,
		},
		batchSize:      malantaBatchSize,
		maxConcurrency: 4,
		maxAttempts:    1,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name implements Provider.
func (p *MalantaProvider) Name() string { return "malanta" }

// AllowedHosts implements Provider.
func (p *MalantaProvider) AllowedHosts() []string {
	if u, err := url.Parse(p.baseURL); err == nil && u.Hostname() != "" {
		return []string{u.Hostname()}
	}
	return []string{malantaHost}
}

// malantaBatchResponse is the shape of both /v1/domains/reputation and
// /v1/ips/reputation batch responses (schema_version 2.0.0, probed live
// 2026-07-05). Only the fields the cascade needs are decoded.
type malantaBatchResponse struct {
	Data []malantaEntry `json:"data"`
}

type malantaEntry struct {
	Indicator struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"indicator"`
	Reputation struct {
		Verdict        string   `json:"verdict"`
		MaliciousScore *float64 `json:"malicious_score"`
	} `json:"reputation"`
}

// Lookup implements Provider.
func (p *MalantaProvider) Lookup(ctx context.Context, indicators []Indicator) (map[Indicator]*Label, error) {
	out := make(map[Indicator]*Label, len(indicators))
	if len(indicators) == 0 {
		return out, nil
	}
	// Reserved-TLD hosts (.example/.test/.invalid) are non-registrable and
	// would be rejected by the API; resolve them to a clean no-data verdict
	// here instead of querying (and failing closed on the rejection).
	indicators = splitReserved(indicators, out)

	// Kind routing is explicit for everything that is not a hostname. The
	// default arm is KindDomain (and any future hostname-shaped Kind);
	// GitHub identities must NOT land there, because lookupDomains applies
	// eTLD+1 reduction, which is meaningless for an "owner/repo" string.
	var domains, ips, repos []Indicator
	for _, ind := range indicators {
		switch ind.Kind {
		case KindIPv4:
			ips = append(ips, ind)
		case KindGitHubRepo, KindGitHubOwner:
			repos = append(repos, ind)
		default:
			domains = append(domains, ind)
		}
	}

	var mu sync.Mutex
	var firstErr error
	recordErr := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup

	if len(domains) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.lookupDomains(ctx, domains, &mu, out); err != nil {
				recordErr(err)
				cancel()
			}
		}()
	}
	if len(ips) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.lookupIPs(ctx, ips, &mu, out); err != nil {
				recordErr(err)
				cancel()
			}
		}()
	}
	if len(repos) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.lookupRepos(ctx, repos, &mu, out); err != nil {
				recordErr(err)
				cancel()
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// lookupDomains reduces each domain Indicator to its registered (eTLD+1)
// form, batches the UNIQUE registered domains, and fans each resulting
// verdict back onto every original Indicator that reduced to it.
func (p *MalantaProvider) lookupDomains(ctx context.Context, domains []Indicator, mu *sync.Mutex, out map[Indicator]*Label) error {
	// registered domain -> original indicators that reduce to it.
	byRegistered := make(map[string][]Indicator, len(domains))
	for _, ind := range domains {
		reg, err := publicsuffix.EffectiveTLDPlusOne(ind.Value)
		if err != nil {
			// Cannot reduce to a registrable domain (e.g. the value is
			// itself a public suffix, which extract.Normalize should
			// already have rejected, or a PSL edge case). Leave absent —
			// the cascade retries once, then fails closed.
			continue
		}
		byRegistered[reg] = append(byRegistered[reg], ind)
	}
	registered := make([]string, 0, len(byRegistered))
	for reg := range byRegistered {
		registered = append(registered, reg)
	}

	labels, err := p.batchLookup(ctx, "/v1/domains/reputation", "domains", registered)
	if err != nil {
		return err
	}

	mu.Lock()
	defer mu.Unlock()
	for reg, lbl := range labels {
		for _, ind := range byRegistered[reg] {
			out[ind] = lbl
		}
	}
	return nil
}

// lookupIPs batches IPv4 Indicators as-is (no reduction).
func (p *MalantaProvider) lookupIPs(ctx context.Context, ips []Indicator, mu *sync.Mutex, out map[Indicator]*Label) error {
	return p.lookupByValue(ctx, "/v1/ips/reputation", "ips", ips, mu, out)
}

// lookupRepos batches GitHub repository AND owner Indicators as-is against
// the code-repos endpoint, which accepts both scopes in one request: an
// "owner/repo" entry answers for the repository, a bare "owner" entry
// answers for the account. Values go up exactly as canonicalized — no
// eTLD+1 reduction (there is no hostname here to reduce) and no
// re-normalization.
//
// One batch covers both scopes on purpose. Server-side latency is
// effectively flat in batch size, so folding repo and owner scopes into a
// single request is the difference between one round trip and two on the
// hook's hot path.
func (p *MalantaProvider) lookupRepos(ctx context.Context, repos []Indicator, mu *sync.Mutex, out map[Indicator]*Label) error {
	return p.lookupByValue(ctx, "/v1/code-repos/reputation", "repos", repos, mu, out)
}

// lookupByValue is the shared "query the indicator values verbatim" path
// used by every Kind that needs no pre-query transformation. It batches the
// values, then fans each returned verdict back onto its Indicator.
//
// A returned value that matches no submitted indicator is DROPPED rather
// than written under a zero-value Indicator key: the response is
// attacker-influencable, and a bogus echo must not be able to manufacture a
// map entry (which would both hide the real indicator's absence and pollute
// the cache under an empty value). Dropping it leaves the real indicator
// absent, which the cascade already handles — retry once, then fail closed.
func (p *MalantaProvider) lookupByValue(ctx context.Context, path, bodyField string, indicators []Indicator, mu *sync.Mutex, out map[Indicator]*Label) error {
	values := make([]string, len(indicators))
	byValue := make(map[string]Indicator, len(indicators))
	for i, ind := range indicators {
		values[i] = ind.Value
		byValue[strings.ToLower(ind.Value)] = ind
	}

	labels, err := p.batchLookup(ctx, path, bodyField, values)
	if err != nil {
		return err
	}

	mu.Lock()
	defer mu.Unlock()
	for v, lbl := range labels {
		ind, ok := byValue[v]
		if !ok {
			continue
		}
		out[ind] = lbl
	}
	return nil
}

// batchLookup chunks values at malantaBatchSize, issues chunk requests with
// bounded concurrency, and returns a map keyed by the LOWERCASED value
// string the response echoed back (the caller maps back to Indicator). The
// FIRST error from any chunk aborts and is returned — other in-flight chunks
// are cancelled via ctx. This keeps the fail-closed contract simple: any
// provider error, at any point in a multi-chunk lookup, denies via the
// normal FailClosed path.
//
// Callers MUST look up with lowercased keys. The lowercasing exists because
// the API's echoed `indicator.value` is not guaranteed to preserve the
// submitted casing: the code-repos endpoint matches case-insensitively and
// echoes the lowercased form (probed live), so keying on the raw echo would
// leave a mixed-case submission unmatched — and an unmatched key is an
// absent entry, which the cascade escalates to a retry and then a
// fail-closed deny. Every value this provider submits is already lowercase
// (domains via extract.Normalize, repos via extract.GitHubFromText, IPv4
// literals trivially), so this is a defensive floor rather than a
// transformation.
func (p *MalantaProvider) batchLookup(ctx context.Context, path, bodyField string, values []string) (map[string]*Label, error) {
	out := make(map[string]*Label, len(values))
	if len(values) == 0 {
		return out, nil
	}

	chunks := chunkStrings(values, p.batchSize)
	sem := make(chan struct{}, p.maxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, chunk := range chunks {
		select {
		case <-ctx.Done():
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(chunk []string) {
			defer wg.Done()
			defer func() { <-sem }()
			entries, err := p.fetchOne(ctx, path, bodyField, chunk)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				cancel()
				return
			}
			mu.Lock()
			for _, e := range entries {
				score := 0.0
				if e.Reputation.MaliciousScore != nil {
					score = *e.Reputation.MaliciousScore
				}
				out[strings.ToLower(e.Indicator.Value)] = &Label{
					Name:           e.Reputation.Verdict,
					MaliciousScore: score,
					ScoreMissing:   e.Reputation.MaliciousScore == nil,
				}
			}
			mu.Unlock()
		}(chunk)
	}
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// fetchOne issues a single batch POST, retrying per the configured retry
// policy on a transient transport error only.
func (p *MalantaProvider) fetchOne(ctx context.Context, path, bodyField string, values []string) ([]malantaEntry, error) {
	attempts := p.maxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		attemptCtx := ctx
		var cancel context.CancelFunc
		if p.attemptTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, p.attemptTimeout)
		}
		entries, err := p.doFetch(attemptCtx, path, bodyField, values)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return entries, nil
		}
		lastErr = err
		if !isTransient(err) || i == attempts-1 || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func (p *MalantaProvider) doFetch(ctx context.Context, path, bodyField string, values []string) ([]malantaEntry, error) {
	body, err := json.Marshal(map[string][]string{bodyField: values})
	if err != nil {
		return nil, fmt.Errorf("%w: build request body: %v", ErrProvider, err)
	}
	endpoint := p.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrProvider, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-api-key", p.apiKey)

	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: http: %v [%w]", ErrProvider, err, errTransient)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: http %d - rotate your key or set MALANTA_API_KEY", ErrAuth, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("%w: http %d: %s", ErrProvider, resp.StatusCode, sanitizeSnippet(snippet, 80))
	}

	var decoded malantaBatchResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrProvider, err)
	}
	return decoded.Data, nil
}

// chunkStrings splits values into groups of at most size (size <= 0 falls
// back to a single chunk containing everything).
func chunkStrings(values []string, size int) [][]string {
	if size <= 0 || size >= len(values) {
		return [][]string{values}
	}
	var out [][]string
	for i := 0; i < len(values); i += size {
		end := i + size
		if end > len(values) {
			end = len(values)
		}
		out = append(out, values[i:end])
	}
	return out
}

func isTransient(err error) bool {
	return errors.Is(err, errTransient)
}
