// Package reputation defines the vendor-neutral seam between the verdict
// cascade and whichever reputation service is answering domain/IP lookups.
// The cascade (internal/verdict) only ever talks to a Provider; concrete
// providers (Malanta, a config-driven generic REST adapter) live in this
// package and are selected by internal/config.Config.Provider via
// NewFromConfig.
package reputation

import (
	"context"
	"errors"
)

// Kind identifies what an Indicator's Value represents. Domains, IPv4
// literals, and GitHub repository/owner identities are supported today;
// IPv6 is a deliberate non-goal until a provider actually offers an
// IPv6-capable endpoint (see KindIPv4 doc).
//
// A Kind is not merely a label: it selects the provider endpoint and the
// pre-query transformation. Anything that is NOT a hostname must have its
// own Kind rather than riding along as KindDomain, because the domain path
// applies hostname-only logic (Malanta's eTLD+1 reduction, the reserved-TLD
// split) that silently corrupts a non-hostname value.
type Kind int

const (
	// KindDomain is a registrable or sub- domain name (already normalized
	// via internal/extract.Normalize: lowercased, punycode, no port/trailing
	// dot).
	KindDomain Kind = iota
	// KindIPv4 is a public IPv4 literal (non-routable ranges are dropped
	// upstream by internal/extract.Normalize before an Indicator is ever
	// built).
	KindIPv4
	// KindGitHubRepo is a GitHub repository identity in canonical
	// "owner/repo" form — lowercased, no host, no ref, no ".git" suffix,
	// no deeper path (see internal/extract.GitHubFromText). It is NOT a
	// hostname and must never be routed through the domain path.
	KindGitHubRepo
	// KindGitHubOwner is a GitHub account (user or organization) identity
	// in canonical bare "owner" form, lowercased. Used when a reference
	// names an account without naming a repository — a profile/org URL, or
	// an owner.github.io Pages host — so an account already known for
	// hosting malicious repositories is still evaluated. Repository scope
	// is preferred whenever the reference carries one.
	KindGitHubOwner
)

// String renders the Kind for logs, cache keys, and audit records.
func (k Kind) String() string {
	switch k {
	case KindDomain:
		return "domain"
	case KindIPv4:
		return "ipv4"
	case KindGitHubRepo:
		return "github_repo"
	case KindGitHubOwner:
		return "github_owner"
	default:
		return "unknown"
	}
}

// ParseKind reverses Kind.String, for cache rows and config/audit records
// that persist the string form. Returns false for anything unrecognized.
func ParseKind(s string) (Kind, bool) {
	switch s {
	case "domain":
		return KindDomain, true
	case "ipv4":
		return KindIPv4, true
	case "github_repo":
		return KindGitHubRepo, true
	case "github_owner":
		return KindGitHubOwner, true
	default:
		return 0, false
	}
}

// Indicator is one candidate host or IP the verdict cascade wants a
// reputation for. Value is always pre-normalized by the extract package.
type Indicator struct {
	Kind  Kind
	Value string
}

// Label is a provider's neutral answer for one Indicator. Name is the
// provider's own verdict/category string (e.g. Malanta's "MALICIOUS" /
// "UNKNOWN", or a generic adapter's mapped field) and is matched
// case-insensitively against config.AllowLabels / config.BlockLabels.
// MaliciousScore is a numeric maliciousness score — 0..1 for
// probability-style providers (Malanta), or a raw count for count-based
// ones (e.g. VirusTotal's engine count); providers must set it to 0 (not
// omit the Label) when no score is available, so the label-set match is
// still meaningful.
//
// ScoreMissing marks a Label whose MaliciousScore was defaulted to 0 because
// the provider's response had no score at all (field absent, or an
// explicit JSON null) — as opposed to MaliciousScore genuinely being 0. This
// distinction matters: a provider can return a flagged verdict (e.g.
// Malanta's "MALICIOUS") with a null score — seen live against
// app.malanta.ai for a domain with no malicious_score — and without this
// flag the cascade (internal/verdict) can't tell that apart from a
// genuine "provider scored this as harmless" 0. ScoreMissing lets the
// cascade log a loud, distinct warning for the former case so operators
// can find it in the decision log, without changing the deny/allow math
// (whether unscored block-listed verdicts should fail closed instead is
// a tracked follow-up).
//
// Zero value (false) is the safe/common case — "this MaliciousScore is a
// real score" — so existing callers and test fixtures that construct a
// Label without setting this field keep their prior behavior; only code
// that actually observed a missing/null score needs to set it true.
type Label struct {
	Name           string
	MaliciousScore float64
	ScoreMissing   bool
}

// Provider is the minimal surface the verdict cascade needs from any
// reputation backend.
//
// Lookup's returned map is keyed by the exact Indicator values passed in.
// A key is OMITTED when the provider could not obtain a definitive answer
// for that indicator — a protocol anomaly (a batch response silently
// missing an entry, or a chunk request that failed outright), NOT the
// ordinary "no data available for this indicator" case. Providers MUST
// surface "no data" as an explicit Label (e.g. Name: "UNKNOWN",
// MaliciousScore: 0) rather than omitting the entry, because the cascade
// treats an absent entry as a signal to retry once and then fail closed
// (see internal/verdict.Compose's absent-entry retry). Getting this wrong either starves
// the cache of a real cacheable "clean/unknown" verdict or turns routine
// "never scanned" lookups into spurious denials.
type Provider interface {
	Lookup(ctx context.Context, indicators []Indicator) (map[Indicator]*Label, error)

	// Name identifies the provider in decision-log records and user-facing
	// deny messages (e.g. "malanta", "generic").
	Name() string

	// AllowedHosts is the set of hostnames this provider is permitted to
	// contact. Populated from the provider's own (validated) configuration;
	// exposed so operators/tests can confirm a provider only talks to what
	// it claims.
	AllowedHosts() []string
}

// ErrProvider is wrapped for any non-auth provider failure (timeout, 5xx,
// network, malformed response). Callers consult config.FailClosed to decide
// the resulting verdict.
var ErrProvider = errors.New("reputation provider error")

// ErrAuth is wrapped for 401/403 responses. Callers surface a rotate-key
// hint to the operator when this is the root cause of a deny.
var ErrAuth = errors.New("reputation provider authentication error")

// errTransient marks an error as a transport-level failure (timeout /
// connection error) eligible for retry. HTTP-status and decode failures are
// NOT marked, so they surface immediately without a retry — a genuine
// malicious verdict (or a 429) must never be softened by a retry.
var errTransient = errors.New("transient")
