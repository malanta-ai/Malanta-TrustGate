package reputation

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/malanta-ai/Malanta-TrustGate/internal/extract"
)

// maxResponseBytes bounds how much of a provider's HTTP response body we
// will ever read. Applies to every provider (Malanta batch responses,
// generic single/batch responses). A malicious or misbehaving endpoint
// sending an unbounded body must not be able to exhaust hook-process
// memory or blow the hook's time budget on I/O.
const maxResponseBytes = 1 << 20 // 1 MiB

// blockCrossHostRedirect refuses any redirect whose target host differs
// from the original request's host. The API key travels as a header on
// every request, and Go's default redirect policy would propagate that
// header to the redirect target — a hostile redirect to an
// attacker-controlled host would silently exfiltrate the key. Same-host
// (path-only) redirects are still permitted so cosmetic URL rewrites at
// the provider's edge do not break lookups.
func blockCrossHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if req.URL.Host != via[0].URL.Host {
		return fmt.Errorf("%w: cross-host redirect blocked: %s -> %s",
			ErrProvider, via[0].URL.Host, req.URL.Host)
	}
	return nil
}

// splitReserved separates indicators whose host sits under an RFC 2606/6761
// reserved TLD (.example / .test / .invalid) from the rest. Those TLDs are
// non-registrable by definition, so no live reputation API can evaluate a
// host under them — querying one makes the API reject the request (e.g.
// Malanta answers HTTP 422 "not a registrable domain"), which, fail-closed,
// would deny every real command that merely mentions such a host.
// extract.Normalize deliberately accepts them so documentation and test
// fixtures work, so they DO reach a provider; every real (live-API)
// provider therefore filters them here and resolves them to a clean
// "UNKNOWN" no-data verdict (written into out), sending only the remaining
// `queryable` indicators upstream. Callers invoke this before starting
// any concurrent lookup, so writing into out here does not race the
// per-lookup goroutines (which only write the queryable keys).
//
// The reserved-TLD test only applies to KindDomain: it is a statement about
// hostnames, and IsReservedTLD reads the value's last dotted label. Any
// other Kind passes through untouched. That guard is load-bearing, not
// cosmetic — a GitHub repository is a "owner/repo" string whose last dotted
// label is whatever the repo name happens to end in, so a real repository
// named e.g. "acme/harness.test" would otherwise be silently resolved to
// UNKNOWN and never queried.
func splitReserved(indicators []Indicator, out map[Indicator]*Label) (queryable []Indicator) {
	for _, ind := range indicators {
		if ind.Kind == KindDomain && extract.IsReservedTLD(ind.Value) {
			out[ind] = &Label{Name: "UNKNOWN"}
			continue
		}
		queryable = append(queryable, ind)
	}
	return queryable
}

// sanitizeSnippet returns at most max runes of body with control characters
// (including newlines) collapsed to spaces, so it is safe to embed in an
// error string that may be surfaced on stdout (the deny user_message).
func sanitizeSnippet(body []byte, max int) string {
	s := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || (r >= 0 && r < 0x20) || r == 0x7f {
			return ' '
		}
		return r
	}, string(body))
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}
