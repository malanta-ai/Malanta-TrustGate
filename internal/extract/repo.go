package extract

import (
	"regexp"
	"strings"
)

// GitHubRefs is the set of canonical GitHub identities found in some piece
// of hook payload. It is deliberately separate from the []string of hosts
// every other extractor returns: an "owner/repo" string is not a hostname,
// and the two must not share a channel where a downstream caller could
// route one through the other's provider endpoint (see reputation.Kind).
//
// Both slices are canonical, lowercased, and de-duplicated:
//
//   - Repos holds "owner/repo" — no host, no scheme, no ref, no ".git"
//     suffix, no deeper path.
//   - Owners holds a bare "owner" (a user or an organization).
//
// Owner scope is a FALLBACK, not an escalation: a reference that names a
// repository yields only the repository. An owner is emitted only when the
// reference itself names nothing narrower — a profile/organization URL, or
// an <owner>.github.io Pages host — so that an account already known for
// hosting malicious repositories is still evaluated. Nothing here expands
// one repository reference into "check the owner too"; that would double
// the fan-out of the common case for no new information.
type GitHubRefs struct {
	Repos  []string
	Owners []string
}

// IsEmpty reports whether no GitHub identity was found.
func (r GitHubRefs) IsEmpty() bool { return len(r.Repos) == 0 && len(r.Owners) == 0 }

// CanonicalGitHubRepo canonicalizes a single human-supplied repository
// reference — "Acme/Backdoor", "acme/backdoor.git", "acme/backdoor@v1", or
// any GitHub URL / SSH remote naming it — to the same "owner/repo" the
// extractors produce, reporting false if it names no repository.
//
// This exists so an operator-facing surface (`trustgate override --repo`)
// resolves a reference through the SAME code the hooks enforce with. A
// separate parser there would eventually disagree, and an override that
// silently fails to match the value the cascade denied on is worse than no
// override at all: the grant looks accepted and the block persists.
//
// A bare "owner/repo" is tried BEFORE the URL scanner, because an owner may
// itself be named "github" (github/docs is a real repository) — routing
// that through the scanner would parse "github" as a host and find nothing.
func CanonicalGitHubRepo(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if segs := splitPathSegments(s); len(segs) == 2 && !strings.Contains(s, "://") {
		owner, repo := segs[0], cleanRepoSegment(segs[1])
		if validGitHubOwner(owner) && validGitHubRepo(repo) {
			return strings.ToLower(owner) + "/" + strings.ToLower(repo), true
		}
	}
	if refs := GitHubFromText(s); len(refs.Repos) > 0 {
		return refs.Repos[0], true
	}
	return "", false
}

// CanonicalGitHubOwner canonicalizes a single human-supplied owner
// reference to the lowercased bare owner the extractors produce.
//
// A reference that names a repository resolves to that repository's owner
// rather than being rejected: "--owner https://github.com/acme/backdoor"
// has one sensible reading (the account behind that repository), and the
// caller echoes back exactly what was granted so the widening is never
// silent. See CanonicalGitHubRepo for why bare forms are tried first.
func CanonicalGitHubOwner(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if !strings.ContainsAny(s, "/:.@") && validGitHubOwner(s) {
		return strings.ToLower(s), true
	}
	if repo, ok := CanonicalGitHubRepo(s); ok {
		return strings.SplitN(repo, "/", 2)[0], true
	}
	if refs := GitHubFromText(s); len(refs.Owners) > 0 {
		return refs.Owners[0], true
	}
	return "", false
}

// maxGitHubRefsPerScan bounds how many distinct identities of EACH scope a
// single scan will accumulate. Overflow is dropped.
//
// The bound is a hot-path and fan-out guard, not a security boundary. Two
// things make dropping acceptable here: the verdict cascade's own
// maxIndicatorsPerEvent (500) would otherwise DENY an event that extracts
// too much, so an unbounded extractor turns a large file into a hard block
// on a legitimate action; and the dense-by-construction files where a
// GitHub URL is a naming convention rather than a fetch instruction are
// excluded upstream (see gitHubScannablePath). 100 is far above any
// realistic count for the surfaces that remain — a large CI workflow tops
// out in the low tens.
//
// KNOWN LIMITATION: an attacker who can put >100 distinct benign GitHub
// references ahead of a malicious one in the same payload pushes the
// malicious one past this cap. That evasion only defeats the read-time
// tripwire; the action itself (clone / install / fetch) still passes
// through the shell / MCP / tool-use hooks, which are the enforcement
// boundary.
const maxGitHubRefsPerScan = 100

// githubTokenRe matches one whitespace/quote/bracket-delimited token that
// contains the literal "github" somewhere inside it — the cheap pre-filter
// that keeps the parser from being handed every word in a 64 KiB script
// body. The excluded characters are the ones that reliably terminate a URL
// in the contexts we scan: whitespace, all three quote styles, angle
// brackets (HTML/markdown), parentheses and brackets (markdown links,
// GitHub Actions ${{ }} expressions), pipes, backslashes, and comma /
// semicolon (delimited lists, so "a,b" yields two tokens rather than one
// unparseable blob).
//
// Requiring "github" INSIDE the token — rather than matching every token
// and filtering afterwards — is what keeps this allocation-cheap on text
// that has no GitHub reference at all.
var githubTokenRe = regexp.MustCompile("(?i)[^\\s'\"`<>|\\\\(){}\\[\\],;]*github[^\\s'\"`<>|\\\\(){}\\[\\],;]*")

// githubShorthandRe matches the "github:owner/repo" shorthand that npm,
// yarn, and bundler accept in place of a full clone URL. The literal
// "github:" prefix is what disambiguates it from an arbitrary path; a bare
// "owner/repo" (also valid npm shorthand) is deliberately NOT matched,
// because it is indistinguishable from any two-segment path.
var githubShorthandRe = regexp.MustCompile(`(?i)\bgithub:([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9._-]+)`)

// githubActionsUsesRe matches a GitHub Actions `uses:` step reference —
// "owner/repo@ref" or "owner/repo/subdir@ref". This is the one GitHub
// reference form that carries no host at all, which is also why it is the
// highest-value one to recognize: a workflow step is executable code
// pulled from a third-party repository.
//
// The trailing "@" is required. Without it the pattern would match any
// two-segment YAML scalar under some other `uses:` key, and a ref is
// mandatory on a real Actions step reference anyway.
var githubActionsUsesRe = regexp.MustCompile(`(?i)\buses:[ \t]*["']?([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9._-]+)(?:/[^\s"'@]+)?@`)

// gitHubHostMarkers are the substrings whose absence from a text blob
// guarantees no GitHub reference is present, letting a scan exit after one
// pass of strings.Contains. "uses:" earns its place because an Actions
// step reference names a repository without naming a host.
var gitHubHostMarkers = []string{"github", "uses:"}

// reservedGitHubNamespaces are first-path-segment values on github.com that
// belong to GitHub itself rather than to an account. Without this set,
// "github.com/features/copilot" would be read as the repository
// "features/copilot" and an ordinary documentation link would be sent to
// the reputation provider as a third-party repository.
//
// This list is best-effort and safe in both directions: a missing entry
// costs one meaningless lookup that comes back UNKNOWN, and a wrong entry
// costs a missed extraction on an account with that exact name (GitHub
// reserves these names, so no such account exists).
var reservedGitHubNamespaces = map[string]struct{}{
	"about": {}, "account": {}, "advisories": {}, "apps": {}, "assets": {},
	"blog": {}, "codespaces": {}, "collections": {}, "contact": {},
	"customer-stories": {}, "dashboard": {}, "enterprise": {}, "events": {},
	"explore": {}, "favicon.ico": {}, "features": {}, "git": {}, "issues": {},
	"join": {}, "login": {}, "logout": {}, "marketplace": {}, "new": {},
	"notifications": {}, "organizations": {}, "pricing": {}, "pulls": {},
	"readme": {}, "robots.txt": {}, "search": {}, "security": {}, "session": {},
	"settings": {}, "signup": {}, "site": {}, "sponsors": {}, "stars": {},
	"topics": {}, "trending": {}, "watching": {},
}

// ownerScopedNamespaces are github.com / api.github.com path prefixes whose
// NEXT segment is an account name rather than a repository owner, e.g.
// "github.com/orgs/acme/repositories" or "api.github.com/users/acme".
var ownerScopedNamespaces = map[string]struct{}{
	"orgs": {}, "users": {}, "sponsors": {},
}

// GitHubFromText scans an arbitrary text blob for GitHub repository and
// owner references and returns them canonicalized. This is the single
// entry point every per-hook GitHub extractor funnels through, so all
// hooks agree on what a canonical identity looks like.
//
// Recognized forms, in every combination of scheme and credential prefix:
//
//	https://github.com/owner/repo(.git)(/tree/main/...)(#anchor)
//	git@github.com:owner/repo.git                (scp-style SSH)
//	ssh://git@github.com/owner/repo.git
//	git+https://github.com/owner/repo@ref#egg=x  (pip)
//	github.com/owner/repo/v2                     (Go module path)
//	raw.githubusercontent.com/owner/repo/ref/path
//	codeload.github.com/owner/repo/tar.gz/ref
//	api.github.com/repos/owner/repo
//	github:owner/repo                            (npm / bundler shorthand)
//	uses: owner/repo/subdir@ref                  (GitHub Actions step)
//
// Owner-scope-only forms:
//
//	https://github.com/owner                     (profile / org page)
//	https://github.com/orgs/owner/...
//	api.github.com/users/owner
//	https://owner.github.io/anything             (Pages host)
//
// Deliberately NOT recognized:
//
//   - Gists (gist.github.com/owner/<id>). A gist id is not a repository
//     name and the provider has no gist scope; emitting the owner from a
//     gist URL was considered and rejected as too weak a signal for v1.
//   - A bare "owner/repo" with no host, scheme, or "github:"/"uses:"
//     marker. It is indistinguishable from any other two-segment path.
//   - Other github.com subdomains (docs., blog., support., status.).
//     They serve GitHub's own content, not user repositories.
func GitHubFromText(text string) GitHubRefs {
	var a githubAcc
	a.scan(text)
	return a.refs()
}

// githubAcc accumulates canonical identities with first-seen ordering,
// de-duplication, and the per-scan cap. Kept unexported so callers that
// scan several surfaces in one hook event (a command plus the script it
// invokes, an MCP destination plus its arguments) share one dedup set
// instead of concatenating separately-deduplicated slices.
type githubAcc struct {
	repos     []string
	owners    []string
	seenRepo  map[string]struct{}
	seenOwner map[string]struct{}
}

func (a *githubAcc) refs() GitHubRefs {
	return GitHubRefs{Repos: a.repos, Owners: a.owners}
}

func (a *githubAcc) addRepo(owner, repo string) {
	if !validGitHubOwner(owner) || !validGitHubRepo(repo) {
		return
	}
	key := strings.ToLower(owner) + "/" + strings.ToLower(repo)
	if a.seenRepo == nil {
		a.seenRepo = make(map[string]struct{}, 4)
	}
	if _, dup := a.seenRepo[key]; dup || len(a.repos) >= maxGitHubRefsPerScan {
		return
	}
	a.seenRepo[key] = struct{}{}
	a.repos = append(a.repos, key)
}

func (a *githubAcc) addOwner(owner string) {
	if !validGitHubOwner(owner) {
		return
	}
	key := strings.ToLower(owner)
	if a.seenOwner == nil {
		a.seenOwner = make(map[string]struct{}, 4)
	}
	if _, dup := a.seenOwner[key]; dup || len(a.owners) >= maxGitHubRefsPerScan {
		return
	}
	a.seenOwner[key] = struct{}{}
	a.owners = append(a.owners, key)
}

// scan runs all three recognizers over one text surface. Safe to call
// repeatedly on the same accumulator.
func (a *githubAcc) scan(text string) {
	if text == "" {
		return
	}
	lower := strings.ToLower(text)
	hasHost := strings.Contains(lower, gitHubHostMarkers[0])
	hasUses := strings.Contains(lower, gitHubHostMarkers[1])
	if !hasHost && !hasUses {
		return
	}
	if hasHost {
		for _, tok := range githubTokenRe.FindAllString(text, maxGitHubRefsPerScan) {
			a.addHostToken(tok)
		}
		for _, m := range githubShorthandRe.FindAllStringSubmatch(text, maxGitHubRefsPerScan) {
			a.addRepo(m[1], cleanRepoSegment(m[2]))
		}
	}
	if hasUses {
		for _, m := range githubActionsUsesRe.FindAllStringSubmatch(text, maxGitHubRefsPerScan) {
			a.addRepo(m[1], cleanRepoSegment(m[2]))
		}
	}
}

// addHostToken parses one candidate token that mentions a GitHub host.
func (a *githubAcc) addHostToken(tok string) {
	host, path, hadScheme := splitGitHubHostPath(tok)
	if host == "" {
		return
	}
	segs := splitPathSegments(path)
	// A URL's ":<port>/" lands in the path as an all-digit first segment.
	// Only strip it when the token actually had a scheme: in scp-style
	// "git@github.com:owner/repo" the same position holds the owner, and
	// an all-digit GitHub username is legal.
	if hadScheme && len(segs) > 0 && isAllDigits(segs[0]) {
		segs = segs[1:]
	}
	switch host {
	case "github.com", "www.github.com":
		a.addWebPath(segs)
	case "raw.githubusercontent.com", "codeload.github.com":
		// Both are content hosts whose path always starts with
		// owner/repo; everything after it is a ref plus a file path.
		a.addOwnerRepoPath(segs)
	case "api.github.com":
		a.addAPIPath(segs)
	case "gist.github.com", "gist.githubusercontent.com",
		"objects.githubusercontent.com":
		// Explicitly out of scope. Gist paths carry a gist id where a
		// repository name would be, and objects.* URLs are opaque signed
		// asset links with no identity in the path at all. Naming them
		// here keeps them from ever falling through to the Pages branch.
	default:
		if owner, ok := pagesOwner(host); ok {
			a.addOwner(owner)
		}
	}
}

// addWebPath handles a path under github.com itself.
func (a *githubAcc) addWebPath(segs []string) {
	if len(segs) == 0 {
		return
	}
	first := strings.ToLower(segs[0])
	if _, ok := ownerScopedNamespaces[first]; ok {
		if len(segs) >= 2 {
			a.addOwner(segs[1])
		}
		return
	}
	if _, reserved := reservedGitHubNamespaces[first]; reserved {
		return
	}
	a.addOwnerRepoPath(segs)
}

// addOwnerRepoPath reads owner from segs[0] and repo from segs[1], ignoring
// everything deeper (a ref, a subdirectory, a release asset name). A path
// with only an owner segment — or whose second segment is not a usable
// repository name — falls back to owner scope, since the account is a real
// identity even when the narrower one is unavailable.
func (a *githubAcc) addOwnerRepoPath(segs []string) {
	if len(segs) == 0 {
		return
	}
	owner := segs[0]
	if len(segs) == 1 {
		a.addOwner(owner)
		return
	}
	repo := cleanRepoSegment(segs[1])
	if !validGitHubRepo(repo) {
		a.addOwner(owner)
		return
	}
	a.addRepo(owner, repo)
}

// addAPIPath handles api.github.com, whose paths are namespaced by resource
// type: /repos/<owner>/<repo>/..., /users/<owner>, /orgs/<owner>.
// Anything else (/search, /rate_limit, /gists) names no repository.
func (a *githubAcc) addAPIPath(segs []string) {
	if len(segs) == 0 {
		return
	}
	switch strings.ToLower(segs[0]) {
	case "repos":
		a.addOwnerRepoPath(segs[1:])
	case "users", "orgs":
		if len(segs) >= 2 {
			a.addOwner(segs[1])
		}
	}
}

// splitGitHubHostPath peels a token down to its host and path components,
// tolerating every prefix shape these references arrive in: an optional
// scheme (including composite ones like pip's "git+https://"), optional
// userinfo ("git@"), and both separators GitHub uses between host and path
// ("/" for URLs, ":" for scp-style SSH).
//
// hadScheme reports whether an explicit "scheme://" was present, which is
// the only thing that makes a ":" after the host a port rather than the
// scp-style path separator.
func splitGitHubHostPath(tok string) (host, path string, hadScheme bool) {
	s := strings.Trim(tok, ".,;:!?*_-#'\"")
	if s == "" {
		return "", "", false
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
		hadScheme = true
	}
	// Userinfo, but only when the "@" precedes the path: in
	// "github.com/owner/repo@v1.2.3" the "@" is a ref delimiter, not a
	// credential separator.
	if at := strings.IndexByte(s, '@'); at >= 0 {
		if slash := strings.IndexByte(s, '/'); slash < 0 || at < slash {
			s = s[at+1:]
		}
	}
	end := strings.IndexAny(s, "/:")
	if end < 0 {
		return strings.ToLower(s), "", hadScheme
	}
	return strings.ToLower(s[:end]), s[end+1:], hadScheme
}

// splitPathSegments splits a URL path into non-empty segments, stopping at
// the first query string or fragment. It also drops a trailing "/" and
// collapses "//".
func splitPathSegments(p string) []string {
	if p == "" {
		return nil
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// cleanRepoSegment reduces a path segment to the bare repository name by
// discarding a ref suffix ("repo@v1.2.3", "repo@main"), a query/fragment
// tail ("repo#egg=name"), and the ".git" suffix a clone URL carries.
//
// The ref is recognized only so it can be REMOVED. A ref is a pointer
// inside a repository, not a separate identity: keeping it would fragment
// the cache and the provider's own key space across every tag and commit
// of the same repository, and the reputation question ("is this repository
// malicious?") is not ref-scoped.
func cleanRepoSegment(seg string) string {
	if i := strings.IndexAny(seg, "@#?"); i >= 0 {
		seg = seg[:i]
	}
	if len(seg) > 4 && strings.EqualFold(seg[len(seg)-4:], ".git") {
		seg = seg[:len(seg)-4]
	}
	return seg
}

// pagesOwner extracts the account name from a GitHub Pages host
// ("<owner>.github.io"), which names an account but no repository.
//
// Requires exactly one label before ".github.io": a GitHub username cannot
// contain a dot, so a multi-label prefix is not a Pages host for an
// account. The bare "github.io" apex is likewise not one.
func pagesOwner(host string) (string, bool) {
	const suffix = ".github.io"
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	owner := host[:len(host)-len(suffix)]
	if owner == "" || strings.Contains(owner, ".") {
		return "", false
	}
	return owner, true
}

// validGitHubOwner applies GitHub's account-name rules: 1-39 characters of
// alphanumerics and hyphens, no leading or trailing hyphen.
func validGitHubOwner(owner string) bool {
	if owner == "" || len(owner) > 39 {
		return false
	}
	if owner[0] == '-' || owner[len(owner)-1] == '-' {
		return false
	}
	for i := 0; i < len(owner); i++ {
		c := owner[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// validGitHubRepo applies GitHub's repository-name rules: 1-100 characters
// of alphanumerics, hyphen, underscore, and dot, with at least one
// alphanumeric so that "." / ".." (relative path segments that reach here
// from a traversal-shaped path) and "---" are rejected.
func validGitHubRepo(repo string) bool {
	if repo == "" || len(repo) > 100 {
		return false
	}
	alnum := false
	for i := 0; i < len(repo); i++ {
		c := repo[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			alnum = true
		case c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return alnum
}
