// Package extract pulls candidate domains from the various Cursor hook payloads
// (shell commands, MCP tool arguments, prompt text, file contents). All
// extractors converge on Normalize so that downstream API lookups see one
// canonical form per host.
package extract

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Normalize lowercases, strips a trailing dot, peels off a :port suffix, and
// converts internationalized labels to punycode (ASCII). It returns "" for
// non-public targets: empty strings, non-routable IP literals (loopback /
// RFC1918 / link-local / CGNAT), bare "localhost", and anything that fails
// IDN processing. Public IP literals (v4 and v6) are returned as-is.
//
// Malanta's reputation API now has an IPv4-capable endpoint
// (/v1/ips/reputation), so public IPs are useful to extract again — the
// caller (verdict.Compose, via reputation.Indicator classification) routes
// IPv4 literals to that endpoint and silently drops any other IP family
// (IPv6) for now, since no provider answers IPv6 lookups yet. Extraction
// itself stays family-agnostic here; kind routing is a downstream concern.
func Normalize(host string) string {
	if host == "" {
		return ""
	}
	h := strings.TrimSpace(host)
	h = strings.Trim(h, "[]") // bracketed IPv6
	h = strings.TrimSuffix(h, ".")
	h = strings.ToLower(h)

	// Strip :port if present (but only if the part after the last colon is numeric,
	// otherwise this would corrupt IPv6 literals).
	if idx := strings.LastIndex(h, ":"); idx > 0 {
		port := h[idx+1:]
		if isAllDigits(port) {
			// Looks like host:port. For IPv6 we should already have stripped brackets
			// above; if the host portion still contains a colon, it's IPv6 without a port.
			candidate := h[:idx]
			if !strings.Contains(candidate, ":") {
				h = candidate
			}
		}
	}

	if h == "" || h == "localhost" {
		return ""
	}

	// IP literal? Reject private/loopback/link-local/CGNAT; pass through
	// public IPs verbatim (see the function doc for why this is safe to do
	// again now that a provider can answer IPv4 reputation lookups).
	if ip := net.ParseIP(h); ip != nil {
		if isNonRoutable(ip) {
			return ""
		}
		return ip.String()
	}

	// IDN -> punycode. We use the Lookup profile (strict) so that mixed-script
	// homographs do not slip through unchanged.
	ascii, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return ""
	}
	if !strings.Contains(ascii, ".") {
		// Bare label (e.g. "router", "kubernetes"); not a public hostname.
		return ""
	}
	// Reject all-digit TLDs. Public TLDs always contain at least one letter
	// (RFC 3696 §2); strings like "1.0" reach here as version numbers fished
	// out of lockfiles and would otherwise be sent to the API.
	if dot := strings.LastIndexByte(ascii, '.'); dot >= 0 && isAllDigits(ascii[dot+1:]) {
		return ""
	}
	// Public Suffix List check. The permissive URL/host regex happily matches
	// any dotted token, which means Go identifiers like "t.Errorf",
	// "config.Defaults", and "context.Background" reach this point as
	// candidate hostnames. None of those right-hand labels are real public
	// TLDs, so the PSL lookup rejects them.
	//
	// We use the lower-level PublicSuffix (not EffectiveTLDPlusOne) because
	// it exposes an `icann` flag distinguishing managed ICANN entries from
	// the default "any unknown label is a valid TLD" rule of RFC 6761. We
	// want to accept ONLY ICANN-managed suffixes, which is what filters out
	// "errorf", "defaults", "background", etc. A host that is itself the
	// public suffix (e.g. "co.uk") is also rejected: it isn't a targetable
	// hostname on its own.
	//
	// The PSL is updated with each release of golang.org/x/net; the cost of
	// missing a freshly-delegated gTLD is a missed extraction (we never get
	// a chance to ask Malanta), which is acceptable - the alternative of
	// false-positiving on every dotted identifier in every allowlisted
	// config file is much worse.
	suffix, icann := publicsuffix.PublicSuffix(ascii)
	if !isAcceptableSuffix(suffix, icann) || suffix == ascii {
		return ""
	}
	return ascii
}

// rfc6761ReservedSuffixes are the IANA-reserved-for-documentation/testing
// TLDs from RFC 6761. They are not in the ICANN-managed PSL section and so
// `publicsuffix.PublicSuffix` reports icann=false for them, but they are
// universally understood to be "valid public-domain shapes that are
// guaranteed never to resolve in production" - exactly what test fixtures
// in this repo (and many others) rely on for safe documentation examples.
// Accepting them keeps Malanta lookups defined for fixtures like
// "mirror.example" and "charts.example" without weakening the gate that
// filters out arbitrary identifiers like "config.Defaults".
//
// Notably absent: `.localhost`. We drop loopback explicitly elsewhere in
// Normalize, before this check is even reached.
var rfc6761ReservedSuffixes = map[string]struct{}{
	"example": {},
	"test":    {},
	"invalid": {},
}

// isAcceptableSuffix returns true for ICANN-managed suffixes (the common
// case) and for the small set of RFC 6761 IANA-reserved suffixes used in
// documentation. Everything else - notably the right-hand label of any Go
// identifier - is rejected.
func isAcceptableSuffix(suffix string, icann bool) bool {
	if icann {
		return true
	}
	_, ok := rfc6761ReservedSuffixes[suffix]
	return ok
}

// IsReservedTLD reports whether host sits under an RFC 2606 / RFC 6761
// reserved TLD (.example, .test, .invalid) — labels that exist specifically
// so they never resolve or get registered. Normalize deliberately accepts
// them (see rfc6761ReservedSuffixes) so documentation and test fixtures
// work, but a live reputation API cannot evaluate a non-registrable host and
// will reject the query (e.g. Malanta answers HTTP 422 "not a registrable
// domain"). A provider that talks to a real API should therefore treat such
// a host as a clean no-data result rather than letting the rejection fail
// closed and deny every real command that merely mentions one. host is
// expected already normalized; the lowercase guard is defensive.
//
// Note this is the bare reserved TLD only: "foo.example" is reserved,
// while "example.com" is an ordinary registrable domain under the real
// .com TLD (RFC 2606 reserves the second level there, not the suffix) and
// is NOT reported here — so it stays queryable, which is what makes it a
// usable placeholder in provider tests.
func IsReservedTLD(host string) bool {
	if host == "" {
		return false
	}
	suffix, _ := publicsuffix.PublicSuffix(strings.ToLower(host))
	_, ok := rfc6761ReservedSuffixes[suffix]
	return ok
}

// NormalizeURL parses a URL string and returns the Normalized host, or "" if
// the URL is unusable. Accepts schemeless inputs by prepending //.
func NormalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") && !strings.HasPrefix(raw, "//") {
		raw = "//" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Host
	if host == "" {
		host = u.Path
	}
	return Normalize(host)
}

// commonFileExtensions is a denylist of TLD-shaped tokens we never want to
// treat as hostnames when they appear bare (no URL context). The set is
// intentionally conservative: ".zip", ".app", and ".dev" are real public
// TLDs and stay OUT of this list even though they also appear as file
// extensions. The cost of an over-broad denylist is a missed deny, which
// breaks fail-closed; the cost of an under-broad one is a false-positive
// extraction, which downstream Malanta lookup will simply not flag.
var commonFileExtensions = map[string]struct{}{
	// archives
	"tgz": {}, "tar": {}, "gz": {}, "bz2": {}, "xz": {}, "7z": {}, "rar": {},
	// scripts / interpreted code
	"sh": {}, "bash": {}, "zsh": {}, "ps1": {}, "py": {}, "rb": {},
	"pl": {}, "lua": {}, "r": {}, "fish": {},
	// binaries / native libs
	"exe": {}, "dll": {}, "dylib": {}, "bin": {},
	// packages / disk images
	"deb": {}, "rpm": {}, "dmg": {}, "iso": {}, "img": {}, "msi": {},
	// text / docs
	"txt": {}, "md": {}, "rst": {}, "log": {}, "csv": {}, "tsv": {},
	// config
	"json": {}, "yml": {}, "yaml": {}, "toml": {}, "ini": {}, "conf": {}, "cfg": {},
	// transient / state
	"lock": {}, "tmp": {}, "bak": {}, "swp": {},
	// web markup / style
	"html": {}, "htm": {}, "css": {}, "scss": {},
	// images
	"jpg": {}, "jpeg": {}, "png": {}, "gif": {}, "webp": {}, "svg": {}, "ico": {},
}

// looksLikeFilename returns true for the kind of "host-shaped" string the
// generic URL regex sometimes hands us out of shell args (e.g. "file.tgz"
// from `scp file.tgz user@host:`). The heuristic is: no scheme, no URL
// context characters (/ : @), and the final label is a known file extension.
//
// Any token with a scheme, path, port, or userinfo is treated as a real URL
// and passed through, because at that point the URL shape is unambiguous.
func looksLikeFilename(m string) bool {
	if strings.Contains(m, "://") {
		return false
	}
	if strings.ContainsAny(m, "/:@") {
		return false
	}
	dot := strings.LastIndexByte(m, '.')
	if dot < 0 || dot == len(m)-1 {
		return false
	}
	ext := strings.ToLower(m[dot+1:])
	_, ok := commonFileExtensions[ext]
	return ok
}

// looksLikeCIDR reports whether a regex match is a CIDR network block
// (10.0.0.0/8, 198.51.100.0/22) rather than a host. The generic URL/host
// regex matches the leading IP and treats the prefix length as a spurious
// URL path (e.g. "198.51.100.0" + path "/22"), so with IP extraction
// re-enabled a CIDR literal — common in network-analysis code, SQL, and
// infra config — would otherwise be extracted as its network address and
// sent to the reputation provider as if it were a host. A CIDR block is a
// range, never a host the command contacts, so dropping it is safe.
// net.ParseCIDR is the authoritative shape check: it accepts only a valid
// IP plus an in-range prefix, so a real URL-to-IP with a non-numeric or
// scheme-bearing path (e.g. "198.51.100.5/health") is NOT matched here and
// still extracts.
func looksLikeCIDR(m string) bool {
	_, _, err := net.ParseCIDR(m)
	return err == nil
}

// extractHosts runs the permissive URL/host regex over text, drops obvious
// filename and CIDR false positives, and returns the de-duplicated set of
// normalized hosts. Used by FromShell, FromMCP, FromPrompt, and FromFile so
// they share exactly one extraction pipeline.
func extractHosts(text string) []string {
	if text == "" {
		return nil
	}
	out := make([]string, 0, 4)
	for _, m := range urlOrHostRe.FindAllString(text, -1) {
		if looksLikeFilename(m) {
			continue
		}
		if looksLikeCIDR(m) {
			continue
		}
		if host := NormalizeURL(m); host != "" {
			out = append(out, host)
		}
	}
	return out
}

// hasURLShape returns true when a regex match carries explicit URL
// syntax beyond a bare 2-label hostname: a scheme (`://`), a
// userinfo segment (`@`), or a path (`/`). Bare host shapes like
// `logger.info`, `process.env`, `pytest.fail`, `app.dev` are
// indistinguishable from attribute / method references in source
// languages — and when their TLD label IS a real public TLD AND
// the host resolves to a registered malicious domain (the
// `logger.info` real-world case captured 2026-05-27), Malanta will
// correctly flag the host and the cascade will deny on every read
// of any file that contains a Python logger call.
//
// The fix: in source/script content where attribute references
// vastly outnumber URL literals, require URL context before
// promoting a regex match to a domain candidate. The cost is
// missing bare-host references in script bodies — but read-time
// extraction is only a tripwire; the shell-exec hook
// (`extract.FromShell`) is the actual enforcement boundary and
// still catches `curl example.com` when the script line runs.
//
// In manifest files (package.json, requirements.txt, Cargo.toml,
// etc.) bare hosts are legitimate registry references and the
// callers use the permissive `extractHosts` instead.
func hasURLShape(m string) bool {
	if strings.Contains(m, "://") {
		return true
	}
	if strings.Contains(m, "@") {
		return true
	}
	if strings.Contains(m, "/") {
		return true
	}
	return false
}

// extractHostsRequireURLShape is the strict-context variant of
// extractHosts. It only emits hosts from regex matches that carry
// explicit URL syntax (scheme / userinfo / path), defeating the
// language-attribute false-positive class (`logger.info`,
// `process.env`, `obj.app`). Used by the read-file path for
// script content; see the hasURLShape doc-comment for the full
// rationale, and shell.go's per-tool config-key scrub for the
// symmetric measure it parallels.
func extractHostsRequireURLShape(text string) []string {
	if text == "" {
		return nil
	}
	out := make([]string, 0, 4)
	for _, m := range urlOrHostRe.FindAllString(text, -1) {
		if !hasURLShape(m) {
			continue
		}
		if looksLikeFilename(m) {
			continue
		}
		if looksLikeCIDR(m) {
			continue
		}
		if host := NormalizeURL(m); host != "" {
			out = append(out, host)
		}
	}
	return out
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isNonRoutable returns true for addresses we never want to look up: loopback,
// unspecified, link-local, multicast, RFC1918 private, and CGNAT (100.64/10).
func isNonRoutable(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return true
	}
	// RFC 6598 CGNAT 100.64.0.0/10
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return true
	}
	return false
}

// IsNonRoutableHost reports whether host (as it would appear in a URL host
// component — bare hostname or IP literal, no port) refers to a target the
// hook subprocess should never be allowed to talk to: loopback, unspecified,
// link-local, multicast, RFC1918 private, CGNAT, or the bare hostnames
// "localhost" / "ip6-localhost".
//
// Exposed so config.Load can reject a misconfigured MALANTA_API_BASE_URL
// pointing at one of these addresses — without it, an attacker who can edit
// the env file could redirect every Malanta lookup to a key-harvester running
// on the same machine, and the rest of the verdict cascade would never know.
func IsNonRoutableHost(host string) bool {
	if host == "" {
		return true
	}
	h := strings.ToLower(host)
	if h == "localhost" || h == "ip6-localhost" {
		return true
	}
	// IPv6 literals in URLs arrive bracketed; strip if present.
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	if ip := net.ParseIP(h); ip != nil {
		return isNonRoutable(ip)
	}
	return false
}

// Dedup canonicalizes (via Normalize) and de-duplicates a slice while keeping
// first-seen order. Empty / non-routable entries are dropped.
func Dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		n := Normalize(s)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}
