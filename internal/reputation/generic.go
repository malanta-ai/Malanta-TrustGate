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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/malanta-ai/Malanta-TrustGate/internal/extract"
)

// GenericMode selects the wire shape a generic provider config speaks.
type GenericMode string

const (
	GenericModeBatch  GenericMode = "batch"
	GenericModeSingle GenericMode = "single"
)

// GenericAuth describes how the provider's secret is sent. The secret value
// itself is read from the environment (EnvVar), never from config.json, so
// it can never be accidentally committed alongside a generic-provider config
// block.
type GenericAuth struct {
	Header string `json:"header"`  // header name, e.g. "x-apikey"
	EnvVar string `json:"env_var"` // env var holding the secret value
	Scheme string `json:"scheme"`  // optional value prefix, e.g. "Bearer " (include trailing space)
}

// GenericResponseMapping extracts a neutral Label out of an arbitrary JSON
// response using dot-separated field paths (no array indexing, no
// expressions) — deliberately minimal so a config file cannot express
// arbitrary computation, only field selection.
type GenericResponseMapping struct {
	// ArrayPath is a dot-path to the array of per-indicator entries in a
	// BATCH response (e.g. "data"). Empty means the response root IS the
	// array.
	ArrayPath string `json:"array_path"`
	// IndicatorValuePath is a dot-path, relative to each batch entry, to the
	// field carrying that entry's own indicator value — used to key results
	// back to the request. Ignored in single mode (there is exactly one
	// indicator per request/response).
	IndicatorValuePath string `json:"indicator_value_path"`
	// VerdictPath is a dot-path (relative to the entry in batch mode, or to
	// the response root in single mode) to a string verdict/category field.
	// Optional — if empty, Label.Name is "" and only ScorePath drives the
	// deny decision (still fully compatible with the cascade's
	// score-threshold check).
	VerdictPath string `json:"verdict_path"`
	// ScorePath is a dot-path to a numeric field. Optional; missing or
	// non-numeric resolves to 0. Vendors that expose raw vote/flag COUNTS
	// rather than a normalized 0..1 probability can still be expressed here
	// — tune MinProbabilityToBlock accordingly (see docs/providers.md).
	ScorePath string `json:"score_path"`
}

// GenericEndpoint is the per-Kind (domain or IPv4) wiring: either a single
// path template (single mode) or a batch path + request body field name
// (batch mode), plus how to read the response.
type GenericEndpoint struct {
	// PathTemplate (single mode) contains one of the placeholders {value},
	// {domain}, or {ip} — all three are accepted as synonyms and are
	// URL-escaped before substitution so an indicator value can never alter
	// the request's host, scheme, or path structure.
	PathTemplate string `json:"path_template"`
	// Path (batch mode) is the fixed endpoint path; the indicator values are
	// sent in the JSON request body under BodyField.
	Path      string `json:"path"`
	BodyField string `json:"body_field"`

	Mapping GenericResponseMapping `json:"mapping"`
}

// GenericProviderConfig is the full config-driven "bring your own REST
// vendor" schema. NOT enabled unless config.Config.Provider == "generic" —
// this provider is never activated by default.
type GenericProviderConfig struct {
	// Name is an optional display name for the configured vendor (e.g.
	// "virustotal"), used everywhere the cascade would otherwise say the
	// generic engine's own name — the deny/warn message shown to the
	// user, the decision log's provider field, and the cache's
	// (provider, kind, value) namespace (see GenericProvider.Name).
	// Empty (the default) falls back to "generic".
	Name    string      `json:"name"`
	BaseURL string      `json:"base_url"`
	Mode    GenericMode `json:"mode"`
	Method  string      `json:"method"` // default: GET (single) / POST (batch)
	Auth    GenericAuth `json:"auth"`

	// AllowedHosts is REQUIRED and non-empty: the exact hostname(s) this
	// provider may contact. BaseURL's own host must be a member. This is
	// the primary SSRF guardrail for a config-driven destination.
	AllowedHosts []string `json:"allowed_hosts"`

	// MaxConcurrency bounds in-flight requests for single mode (bounded
	// fan-out over cache misses) and concurrent chunk requests for batch
	// mode. Defaults to 2 if unset.
	MaxConcurrency int `json:"max_concurrency"`

	Domain *GenericEndpoint `json:"domain"` // nil = this provider does not answer domain lookups
	IP     *GenericEndpoint `json:"ip"`     // nil = this provider does not answer IPv4 lookups
}

// Validate checks the config for the SSRF/misconfiguration guardrails
// (H2): HTTPS-only, an explicit non-empty host allowlist that the base URL
// itself must satisfy, a routable host, a recognized mode, and at least one
// usable endpoint with well-formed templates. Called once at provider
// construction (fail-closed at config.Load, same posture as
// validateAPIBaseURL for the Malanta provider).
//
// KNOWN LIMITATION: this validates the CONFIGURED host, not what it
// resolves to at request time (no DNS-rebinding / IP-pinning defense). A
// hostile or compromised DNS answer for an allowlisted hostname is not
// caught here — treat AllowedHosts as "hostnames I trust the operator's DNS
// for," not an IP-level guarantee.
func (c GenericProviderConfig) Validate() error {
	if c.BaseURL == "" {
		return errors.New("generic provider: base_url is empty")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("generic provider: base_url: parse: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("generic provider: base_url: scheme must be https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("generic provider: base_url: missing host")
	}
	if extract.IsNonRoutableHost(host) {
		return fmt.Errorf("generic provider: base_url host %q is loopback/private/link-local", host)
	}
	if len(c.AllowedHosts) == 0 {
		return errors.New("generic provider: allowed_hosts must be non-empty")
	}
	if !hostAllowed(host, c.AllowedHosts) {
		return fmt.Errorf("generic provider: base_url host %q is not in allowed_hosts", host)
	}
	switch c.Mode {
	case GenericModeBatch, GenericModeSingle:
	default:
		return fmt.Errorf("generic provider: mode must be %q or %q, got %q", GenericModeBatch, GenericModeSingle, c.Mode)
	}
	if c.Domain == nil && c.IP == nil {
		return errors.New("generic provider: at least one of domain / ip must be configured")
	}
	for kind, ep := range map[string]*GenericEndpoint{"domain": c.Domain, "ip": c.IP} {
		if ep == nil {
			continue
		}
		if c.Mode == GenericModeSingle {
			if !strings.Contains(ep.PathTemplate, "{value}") &&
				!strings.Contains(ep.PathTemplate, "{domain}") &&
				!strings.Contains(ep.PathTemplate, "{ip}") {
				return fmt.Errorf("generic provider: %s.path_template must contain {value}/{domain}/{ip}", kind)
			}
		} else {
			if ep.Path == "" || ep.BodyField == "" {
				return fmt.Errorf("generic provider: %s.path and %s.body_field are required in batch mode", kind, kind)
			}
		}
	}
	// Auth completeness, structural half: if auth is DECLARED (an auth
	// header is configured), the config must at least NAME the env var that carries
	// the secret. The runtime presence check (that the env var is actually
	// set) lives in config.validateProviderConfig, so this structural
	// Validate stays free of process-environment coupling — a config file
	// can be shape-checked (tests, docs examples) without the secret being
	// exported.
	if c.Auth.Header != "" && strings.TrimSpace(c.Auth.EnvVar) == "" {
		return errors.New("generic provider: auth.header is set but auth.env_var is empty — name the env var that holds the secret")
	}
	return nil
}

func hostAllowed(host string, allowed []string) bool {
	hl := strings.ToLower(host)
	for _, a := range allowed {
		if strings.ToLower(strings.TrimSpace(a)) == hl {
			return true
		}
	}
	return false
}

// GenericProvider implements Provider against a config-declared REST
// vendor. This is the ENGINE that is officially supported; specific vendor
// CONFIGS (VirusTotal, etc.) are community/best-effort — see
// docs/providers.md and SUPPORT.md.
type GenericProvider struct {
	cfg    GenericProviderConfig
	apiKey string
	http   *http.Client

	attemptTimeout      time.Duration
	maxAttempts         int
	concurrencyOverride int
}

// GenericOption configures a GenericProvider.
type GenericOption func(*GenericProvider)

// WithGenericRetry mirrors WithMalantaRetry for the generic provider.
func WithGenericRetry(attemptTimeout time.Duration, maxAttempts int) GenericOption {
	return func(p *GenericProvider) {
		p.attemptTimeout = attemptTimeout
		if maxAttempts >= 1 {
			p.maxAttempts = maxAttempts
		}
	}
}

// WithGenericConcurrency overrides how many in-flight requests
// concurrency() allows, taking precedence over both
// GenericProviderConfig.MaxConcurrency and the built-in default of 2 (see
// concurrency()). n <= 0 is a no-op — this mirrors config.Config.
// ProviderMaxConcurrency's "0 means no override" convention, so
// hookrunner/doctor can call this unconditionally with the configured
// value regardless of whether the operator set one.
func WithGenericConcurrency(n int) GenericOption {
	return func(p *GenericProvider) {
		if n > 0 {
			p.concurrencyOverride = n
		}
	}
}

// NewGeneric validates cfg and returns a GenericProvider. Returns an error
// (never a partially-usable provider) if validation fails — the caller
// (config.Load / the reputation factory) treats that as a fail-closed
// bootstrap error, matching validateAPIBaseURL's posture for Malanta.
func NewGeneric(cfg GenericProviderConfig, opts ...GenericOption) (*GenericProvider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &GenericProvider{
		cfg:         cfg,
		apiKey:      "",
		maxAttempts: 1,
		http: &http.Client{
			CheckRedirect: blockCrossHostRedirect,
		},
	}
	if cfg.Auth.EnvVar != "" {
		p.apiKey = os.Getenv(cfg.Auth.EnvVar)
	}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Name returns the configured display name (GenericProviderConfig.Name),
// falling back to "generic" when unset. This is the ONLY name the rest of
// the cascade ever sees for this provider — the deny/warn message text,
// the decision log's provider field, and cache namespacing all key off it
// (see internal/verdict.Compose, which sets its own providerName from
// this method) — so setting Name in config.json is enough to make every
// user-facing surface say the actual vendor instead of "generic".
func (p *GenericProvider) Name() string {
	if p.cfg.Name != "" {
		return p.cfg.Name
	}
	return "generic"
}

func (p *GenericProvider) AllowedHosts() []string {
	out := make([]string, len(p.cfg.AllowedHosts))
	copy(out, p.cfg.AllowedHosts)
	return out
}

// concurrency resolves the in-flight-request bound with this precedence:
// an explicit WithGenericConcurrency override (config.Config.
// ProviderMaxConcurrency, when the operator set it) beats the per-vendor
// config.json max_concurrency, which beats the built-in default of 2.
func (p *GenericProvider) concurrency() int {
	if p.concurrencyOverride > 0 {
		return p.concurrencyOverride
	}
	if p.cfg.MaxConcurrency > 0 {
		return p.cfg.MaxConcurrency
	}
	return 2
}

// Lookup implements Provider, routing domain/IPv4 indicators to their
// respective endpoint config. An indicator whose Kind has NO configured
// endpoint is resolved immediately to an empty Label (no verdict, no
// score) rather than left absent — this is a static "this provider doesn't
// answer that kind" fact, not a transient anomaly, so it must not trigger
// the cascade's retry-then-fail-closed path.
func (p *GenericProvider) Lookup(ctx context.Context, indicators []Indicator) (map[Indicator]*Label, error) {
	out := make(map[Indicator]*Label, len(indicators))
	if len(indicators) == 0 {
		return out, nil
	}
	// Reserved-TLD hosts (.example/.test/.invalid) are non-registrable and
	// cannot be evaluated by a live API; resolve them to a clean no-data
	// verdict here instead of querying (and risking a fail-closed error).
	indicators = splitReserved(indicators, out)

	var domains, ips []Indicator
	for _, ind := range indicators {
		switch ind.Kind {
		case KindIPv4:
			ips = append(ips, ind)
		case KindGitHubRepo, KindGitHubOwner:
			// GitHub repository reputation is a Malanta-only capability
			// today: there is no vendor-neutral request/response shape to
			// map a config-driven adapter onto, so the generic adapter has
			// no repo endpoint to configure.
			//
			// This arm is a GUARD, not a stub. Falling through to the
			// domain arm would send "owner/repo" to the configured domain
			// endpoint, which answers about a value that is not a
			// hostname — a nonsense query whose most likely outcomes are
			// an HTTP 4xx (fail-closed deny of a perfectly good command)
			// or, worse, a confident verdict about the wrong thing.
			// Resolving to an empty Label instead is the same "this
			// provider has nothing to say" contract the unconfigured
			// endpoints below use: no HTTP request, no error, and the
			// cascade sees an explicit no-data answer rather than an
			// absent entry (which it would escalate to a fail-closed
			// deny).
			out[ind] = &Label{}
		default:
			domains = append(domains, ind)
		}
	}
	if p.cfg.Domain == nil {
		for _, ind := range domains {
			out[ind] = &Label{}
		}
		domains = nil
	}
	if p.cfg.IP == nil {
		for _, ind := range ips {
			out[ind] = &Label{}
		}
		ips = nil
	}

	var mu sync.Mutex
	var firstErr error
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	run := func(ep *GenericEndpoint, kindIndicators []Indicator) {
		defer wg.Done()
		if len(kindIndicators) == 0 {
			return
		}
		var err error
		if p.cfg.Mode == GenericModeBatch {
			err = p.lookupBatch(ctx, ep, kindIndicators, &mu, out)
		} else {
			err = p.lookupSingle(ctx, ep, kindIndicators, &mu, out)
		}
		if err != nil {
			mu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
			cancel()
		}
	}
	if len(domains) > 0 {
		wg.Add(1)
		go run(p.cfg.Domain, domains)
	}
	if len(ips) > 0 {
		wg.Add(1)
		go run(p.cfg.IP, ips)
	}
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// lookupSingle issues one request per indicator with bounded concurrency.
func (p *GenericProvider) lookupSingle(ctx context.Context, ep *GenericEndpoint, indicators []Indicator, mu *sync.Mutex, out map[Indicator]*Label) error {
	sem := make(chan struct{}, p.concurrency())
	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error

	for _, ind := range indicators {
		wg.Add(1)
		sem <- struct{}{}
		go func(ind Indicator) {
			defer wg.Done()
			defer func() { <-sem }()
			lbl, err := p.fetchSingle(ctx, ep, ind.Value)
			if err != nil {
				errOnce.Do(func() { firstErr = err })
				return
			}
			mu.Lock()
			out[ind] = lbl
			mu.Unlock()
		}(ind)
	}
	wg.Wait()
	return firstErr
}

func (p *GenericProvider) fetchSingle(ctx context.Context, ep *GenericEndpoint, value string) (*Label, error) {
	escaped := url.PathEscape(value)
	path := ep.PathTemplate
	path = strings.ReplaceAll(path, "{value}", escaped)
	path = strings.ReplaceAll(path, "{domain}", escaped)
	path = strings.ReplaceAll(path, "{ip}", escaped)

	method := p.cfg.Method
	if method == "" {
		method = http.MethodGet
	}

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
		root, err := p.doRequest(attemptCtx, method, path, nil)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			score, scored := dotGetFloatOK(root, ep.Mapping.ScorePath)
			return &Label{
				Name:           dotGetString(root, ep.Mapping.VerdictPath),
				MaliciousScore: score,
				ScoreMissing:   !scored,
			}, nil
		}
		lastErr = err
		if !isTransient(err) || i == attempts-1 || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// lookupBatch chunks indicators is NOT performed for the generic provider
// today (it forwards the whole set in one request) — operators using a
// vendor with its own per-request cap should keep events under it; a
// future enhancement can add config-driven chunking symmetric to Malanta's.
func (p *GenericProvider) lookupBatch(ctx context.Context, ep *GenericEndpoint, indicators []Indicator, mu *sync.Mutex, out map[Indicator]*Label) error {
	byValue := make(map[string]Indicator, len(indicators))
	values := make([]string, len(indicators))
	for i, ind := range indicators {
		values[i] = ind.Value
		byValue[ind.Value] = ind
	}

	method := p.cfg.Method
	if method == "" {
		method = http.MethodPost
	}
	body, err := json.Marshal(map[string][]string{ep.BodyField: values})
	if err != nil {
		return fmt.Errorf("%w: build request body: %v", ErrProvider, err)
	}

	attempts := p.maxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var root any
	var lastErr error
	for i := 0; i < attempts; i++ {
		attemptCtx := ctx
		var cancel context.CancelFunc
		if p.attemptTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, p.attemptTimeout)
		}
		root, err = p.doRequest(attemptCtx, method, ep.Path, bytes.NewReader(body))
		if cancel != nil {
			cancel()
		}
		if err == nil {
			lastErr = nil
			break
		}
		lastErr = err
		if !isTransient(err) || i == attempts-1 || ctx.Err() != nil {
			break
		}
	}
	if lastErr != nil {
		return lastErr
	}

	entries, ok := dotGetArray(root, ep.Mapping.ArrayPath)
	if !ok {
		return fmt.Errorf("%w: batch response missing array at %q", ErrProvider, ep.Mapping.ArrayPath)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, e := range entries {
		key := dotGetString(e, ep.Mapping.IndicatorValuePath)
		ind, ok := byValue[key]
		if !ok {
			continue
		}
		score, scored := dotGetFloatOK(e, ep.Mapping.ScorePath)
		out[ind] = &Label{
			Name:           dotGetString(e, ep.Mapping.VerdictPath),
			MaliciousScore: score,
			ScoreMissing:   !scored,
		}
	}
	return nil
}

// doRequest issues one HTTP request and decodes the JSON body into a
// generic any (map[string]any / []any tree) for dot-path extraction. Body
// reads are capped at maxResponseBytes.
func (p *GenericProvider) doRequest(ctx context.Context, method, path string, body io.Reader) (any, error) {
	endpoint := p.cfg.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrProvider, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.cfg.Auth.Header != "" && p.apiKey != "" {
		req.Header.Set(p.cfg.Auth.Header, p.cfg.Auth.Scheme+p.apiKey)
	}

	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: http: %v [%w]", ErrProvider, err, errTransient)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: http %d - check the provider's API key", ErrAuth, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("%w: http %d: %s", ErrProvider, resp.StatusCode, sanitizeSnippet(snippet, 80))
	}

	var decoded any
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrProvider, err)
	}
	return decoded, nil
}

// dotGet resolves a dot-separated path against a decoded JSON tree
// (map[string]any nesting). Deliberately minimal: no array indexing, no
// expressions — a config file can only select a field, never compute one.
func dotGet(v any, path string) (any, bool) {
	if path == "" {
		return v, true
	}
	cur := v
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func dotGetString(v any, path string) string {
	val, ok := dotGet(v, path)
	if !ok {
		return ""
	}
	s, _ := val.(string)
	return s
}

func dotGetFloat(v any, path string) float64 {
	f, _ := dotGetFloatOK(v, path)
	return f
}

// dotGetFloatOK is dotGetFloat plus a found flag: false when the path is
// absent, the value is JSON null, or the value isn't numeric. Callers that
// need to distinguish "provider scored this at 0" from "provider didn't
// score this at all" (see reputation.Label.ScoreMissing) should use this
// instead of dotGetFloat.
func dotGetFloatOK(v any, path string) (float64, bool) {
	val, ok := dotGet(v, path)
	if !ok || val == nil {
		return 0, false
	}
	switch x := val.(type) {
	case float64:
		return x, true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func dotGetArray(v any, path string) ([]any, bool) {
	if path == "" {
		arr, ok := v.([]any)
		return arr, ok
	}
	val, ok := dotGet(v, path)
	if !ok {
		return nil, false
	}
	arr, ok := val.([]any)
	return arr, ok
}
