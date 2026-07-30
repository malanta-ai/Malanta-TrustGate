package extract

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// maxScriptBytes bounds how much of a candidate script body we'll read
// during the script-follow pass. 64 KiB is large enough for any realistic
// shell / python / node script and small enough to fit comfortably inside
// the Cursor hook timeout even if the file is on a slow filesystem.
const maxScriptBytes = 64 * 1024

// shellInterpreters are the binary names that, when present as the head of
// a tokenized command, indicate the next non-flag argument is a script
// path we should read and scan.
var shellInterpreters = map[string]struct{}{
	"bash": {}, "sh": {}, "zsh": {}, "fish": {}, "ksh": {}, "dash": {},
	"csh": {}, "tcsh": {},
}

// manifestFlagsByTool maps a package-manager binary to the flags that take
// a dependency-manifest PATH as their value.
//
// This is the counterpart to the read-file side's decision to treat
// dependency files as records rather than actions (see
// gitHubScannablePath): the file itself is not an action, but the install
// command that consumes it IS, and it names the file in argv. Following it
// here catches what a read-time path allowlist structurally cannot — the
// path is whatever the user typed, so `pip install -r reqs/prod.txt` or
// `-r myrequirements.txt` are covered without guessing filenames.
//
// Only flags whose value is unambiguously a manifest path belong here. A
// flag that sometimes takes a path and sometimes something else would make
// the following stat-and-fail on ordinary commands, wasting hook budget.
var manifestFlagsByTool = map[string]map[string]struct{}{
	"pip":    {"-r": {}, "--requirement": {}, "-c": {}, "--constraint": {}},
	"pip3":   {"-r": {}, "--requirement": {}, "-c": {}, "--constraint": {}},
	"pip2":   {"-r": {}, "--requirement": {}, "-c": {}, "--constraint": {}},
	"uv":     {"-r": {}, "--requirement": {}, "-c": {}, "--constraint": {}},
	"cargo":  {"--manifest-path": {}},
	"bundle": {"--gemfile": {}},
}

// langInterpreters covers the non-shell language runtimes that follow the
// same `interpreter <flags...> <script>` shape.
var langInterpreters = map[string]struct{}{
	"python": {}, "python2": {}, "python3": {},
	"node": {}, "nodejs": {}, "deno": {}, "bun": {},
	"ruby": {}, "perl": {}, "php": {}, "lua": {}, "tcl": {},
	"pwsh": {}, "powershell": {},
	"rscript": {},
}

// scriptExtensions is the set of file extensions that we treat as
// "executable script" for the direct-invocation case (./foo.sh, ./bar.py).
// Bare-name binaries without one of these extensions aren't followed
// because tokens like "./mybinary" are ambiguous (could be a compiled
// binary the user is testing) and the cost of mis-following is wasting
// time reading non-text content.
var scriptExtensions = map[string]struct{}{
	".sh": {}, ".bash": {}, ".zsh": {}, ".fish": {}, ".ksh": {},
	".py": {}, ".js": {}, ".rb": {}, ".pl": {}, ".php": {},
	".lua": {}, ".ps1": {}, ".psm1": {}, ".r": {},
}

// nonShellSourceExtensions is the subset of script extensions whose bodies are
// NON-shell programming-language source, where `.` is the member-access
// operator and bare dotted tokens (subprocess.run, resp.data, x.id) are
// attribute references — NOT hostnames — even though their right-hand labels
// (.run .data .id ...) are real ICANN gTLDs. Content of these shapes is
// extracted with URL shape REQUIRED (see extractHostsRequireURLShape), so a
// genuine network literal (urlopen("http://..."), a scheme/path/userinfo URL)
// is still caught while the member-access false-positive class is suppressed.
//
// Shell extensions (.sh/.bash/.zsh/.fish/.ksh) are intentionally EXCLUDED:
// their bodies are shell where a bare `curl host` / `target="host"` is a
// first-class network reference, so they keep the permissive shell pipeline.
// This mirrors the read-file hook's per-content-shape routing and the inline
// `-c` / interpreter-heredoc guards.
var nonShellSourceExtensions = map[string]struct{}{
	".py": {}, ".js": {}, ".mjs": {}, ".cjs": {}, ".ts": {},
	".rb": {}, ".pl": {}, ".php": {}, ".lua": {}, ".r": {},
	".ps1": {}, ".psm1": {},
}

// urlOrHostRe matches a URL or a bare host that looks like a public hostname.
// It is intentionally permissive; downstream Normalize filters out non-routable
// targets. We require at least one dot to skip on local commands and binaries.
var urlOrHostRe = regexp.MustCompile(
	`(?i)` +
		`(?:[a-z][a-z0-9+\-.]*://)?` + // optional scheme
		`(?:[a-z0-9_.\-]+@)?` + // optional userinfo (e.g. git@)
		`(?:` +
		`(?:xn--[a-z0-9\-]+|[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)` + // first label
		`(?:\.(?:xn--[a-z0-9\-]+|[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?))+` + // additional labels
		`|` +
		`\[[0-9a-f:]+\]` + // bracketed IPv6
		`|` +
		`(?:\d{1,3}\.){3}\d{1,3}` + // IPv4
		`)` +
		`(?::\d{1,5})?` + // optional :port
		`(?:/[^\s'"<>]*)?`, // optional path
)

// gitSSHRe matches scp-style git URLs ("git@example.com:org/repo.git"). The
// trailing [^\s...]* consumes the whole path so the caller can scrub the full
// match out before running the generic URL regex (otherwise "repo.git" would
// be picked up as if ".git" were a TLD).
var gitSSHRe = regexp.MustCompile(`(?i)\b([a-z0-9_.\-]+)@([a-z0-9.\-]+\.[a-z]{2,}):[^\s'"<>]*`)

// CLI config-key scrubbing regexes. Each captures group 1 = the dotted
// config-key argument to a known "<tool> config" / "<tool> configure"
// subcommand. The caller blanks out that byte range before the generic
// URL regex runs, so config keys like user.email / core.editor /
// default.region (whose rightmost label IS a real ICANN TLD on the PSL)
// stop being extracted as if they were hostnames.
//
// Each regex requires the leading subcommand context, so a hostile
// domain in a normal curl/wget invocation is unaffected. The VALUE arg
// of `set` subcommands is NOT captured because values legitimately
// contain URLs (e.g. "git config remote.origin.url https://...").
//
// Flags that take a separate-token value (--file <path>, --blob <id>)
// are intentionally not handled — matching them robustly would require
// per-flag knowledge that RE2 can't backtrack into, and the worst case
// when the regex misses is "FP not suppressed for this variant" with no
// change to security posture. Add per-tool knowledge here as new variants
// surface.

// gitConfigKeyRe matches "git config [<switch>...] <KEY>" and captures
// the dotted KEY. Handles --flag and --flag=value switches; not the
// --flag <value> separate-token form (see package note above).
var gitConfigKeyRe = regexp.MustCompile(
	`(?i)\bgit\s+config\b(?:\s+-[^\s]+(?:=[^\s]+)?)*\s+([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)\b`,
)

// gitDashCKeyRe matches git's per-command config override form
// "-c <KEY>=<VALUE>" and captures the dotted KEY. The `-c KEY=VAL`
// flag is functionally equivalent to running `git config KEY VAL`
// for the duration of one invocation, and it's heavily used by CI
// pipelines:
//
//	git -c user.email=bot@ci.example -c user.name=bot commit -m "..."
//	git -c http.proxy=http://corp.proxy:8080 fetch ...
//	git -c core.editor=vim rebase -i HEAD~3
//
// Before this scrub, the dotted KEY (`user.email`, `http.proxy`,
// `core.editor`) is left in the post-`gitConfigKeyRe` byte stream and
// the per-segment regex pass extracts it as a hostname — which
// Malanta correctly labels Suspicius (the KEY ends in a real ICANN
// TLD), denying the entire git invocation. Scrubbing the KEY byte
// range here leaves the VALUE (including the leading `=`) intact, so
// `git -c user.email=bot@ci.example fetch` still gets `ci.example`
// extracted from the value side if the surrounding subcommand is a
// network op (fetch / push / clone / pull / submodule).
//
// Pattern notes:
//   - No `\bgit\b` anchor: it would force the regex to match starting
//     at `git`, which means FindAllSubmatchIndex (non-overlapping)
//     finds at most ONE `-c KEY=` per command. Real CI invocations
//     chain multiple `-c KEY=VAL` flags, and we need to scrub all of
//     them. We anchor instead on the token boundary preceding `-c`
//     (`(?:^|\s)`), which catches both the first and the subsequent
//     `-c` flags. The FP risk of matching a non-git tool's `-c KEY=`
//     is bounded by the structurally-required PSL-TLD-shaped KEY —
//     no common non-git tool uses `-c <dotted>=<value>` syntax.
//   - The trailing `=` is included in the regex but NOT in the
//     KEY capture group, so it stays in the byte stream when we
//     blank `scrub[m[2]:m[3]]`.
var gitDashCKeyRe = regexp.MustCompile(
	`(?i)(?:^|\s)-c\s+([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)=`,
)

// npmConfigKeyRe handles npm / pnpm / yarn `config get|set|delete <KEY>`.
// npm config keys allow hyphens (e.g. "cache.lock-retries"), so the key
// class includes `-` here unlike the git/aws/gcloud cases.
var npmConfigKeyRe = regexp.MustCompile(
	`(?i)\b(?:npm|pnpm|yarn)\s+config\s+(?:get|set|delete)\s+([a-z][a-z0-9_\-]*(?:\.[a-z][a-z0-9_\-]*)+)`,
)

// kubectlConfigKeyRe handles `kubectl config set|unset <PROPERTY>` where
// PROPERTY is dotted (e.g. "users.alice.client-key-data",
// "clusters.prod.server").
var kubectlConfigKeyRe = regexp.MustCompile(
	`(?i)\bkubectl\s+config\s+(?:set|unset)\s+([a-z][a-z0-9_\-]*(?:\.[a-z][a-z0-9_\-]*)+)`,
)

// awsConfigureKeyRe handles `aws configure set|get <VARNAME>` where
// VARNAME may be dotted with TLD-shaped suffix (e.g. "default.region",
// "profile.foo.region").
var awsConfigureKeyRe = regexp.MustCompile(
	`(?i)\baws\s+configure\s+(?:set|get)\s+([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)`,
)

// gcloudConfigKeyRe handles `gcloud config set|unset|get(-value)? <KEY>`
// where KEY is dotted (e.g. "core.project", "compute.region").
var gcloudConfigKeyRe = regexp.MustCompile(
	`(?i)\bgcloud\s+config\s+(?:set|unset|get(?:-value)?)\s+([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)`,
)

// gitMessageRe scrubs the VALUE of `-m <msg>` / `--message=<msg>` /
// `--message <msg>` on the git subcommands that actually take a
// human-authored message argument: commit / tag / merge / stash
// (push|save) / notes (add|append|edit).
//
// Why this exists: commit messages are local repository metadata
// that lands in the .git object database, never on the wire of the
// commit operation itself. URLs, emails, and dotted-config-key
// tokens mentioned in a commit message are not network destinations;
// extracting them produces a fail-closed deny on legitimate
// `git commit -m "..."` invocations that describe what the change
// does — including, recursively, the commit message of THIS fix,
// which is why the change is necessary.
//
// What we DON'T scrub on purpose:
//   - `git revert -m <parent-number>` and `git cherry-pick -m
//     <parent-number>` — these `-m` flags carry a small integer
//     selecting which parent of a merge commit to favor, not a
//     message. Neither subcommand is in the alternation below, so
//     the regex doesn't fire on them and any extractable
//     content in their args (unlikely, but possible) is preserved.
//   - `-F <file>` / `--file=<file>` — these read the message from a
//     file, which means the SHELL COMMAND LINE doesn't contain the
//     message text at all. No scrub needed; the file content is
//     not on the bytes Cursor hands the hook.
//
// What we accept by scrubbing the value: a hostile commit message
// CAN smuggle an exfil URL into the repository's commit history,
// and that history reaches the network when the agent later runs
// `git push`. The push hook event sees `git push origin main` —
// no message text — so the smuggled URL is invisible at push time.
// We accept this narrow exfiltration channel because (a) the
// alternative produces fail-closed denials on every legitimate
// commit message containing a PSL-TLD-shaped token, which trains
// users to disable the hook, and (b) the threat assumes an
// already-compromised agent willing to commit + push to a public
// remote of the attacker's choosing — at that point the same agent
// has many easier exfiltration channels than commit metadata.
//
// Pattern notes:
//   - The git-subcommand alternation must be a single non-capturing
//     group; otherwise the value's capture index shifts.
//   - `[^|;&\n]*?` keeps the lazy walk from crossing into a NEXT
//     statement that happens to start with `-m`.
//   - The value alternation supports double-quoted ("..."),
//     single-quoted ('...'), and bare-token values, plus
//     `--message=` with the value attached by `=`. The captured
//     value includes the surrounding quotes (if any), which the
//     scrub loop blanks — `"hello"` becomes `       ` and
//     `'hello'` becomes `       `, both of which extract no hosts.
//   - Escaped quotes inside the message (`-m "she said \"hi\""`)
//     are a known limitation; the regex stops at the first inner
//     quote. The remaining tail of the message stays in the byte
//     stream and any TLD-shaped tokens there would still extract.
//     Rare enough in practice not to justify a full shell-quoting
//     parser in the hot path.
var gitMessageRe = regexp.MustCompile(
	`(?i)\bgit\s+(?:commit|tag|merge|stash\s+(?:push|save)|notes\s+(?:add|append|edit))\b[^|;&\n]*?(?:\s(?:-m|--message)\s+|\s--message=)("[^"]*"|'[^']*'|\S+)`,
)

// configKeyScrubREs is the iteration order for the scrub pass in
// FromShellInDir. Order is irrelevant for correctness because each
// regex anchors on a disjoint subcommand prefix.
var configKeyScrubREs = []*regexp.Regexp{
	gitConfigKeyRe,
	gitDashCKeyRe,
	gitMessageRe,
	npmConfigKeyRe,
	kubectlConfigKeyRe,
	awsConfigureKeyRe,
	gcloudConfigKeyRe,
}

// percentEncodedRe matches a URL-percent-encoded byte sequence
// (%XX where XX is two hex digits). The shell scrub blanks out
// every match before the generic host regex runs, defeating the
// "URL-encoded character inside a command-line argument confuses
// the host extractor" FP class. The canonical example is the
// CTI-analyst report (2026-05-28): a curl/HTTP API call with the
// query parameter `email=user%40mail.example` got the bytes
// `40mail.example` extracted as a candidate host (`%` is not in the
// userinfo character class, so the regex slides forward past it
// and treats `40` as the first label of a `40mail.example`
// hostname). Malanta then classified `40mail.example` as Malicious
// at 0.9885 and denied the whole command.
//
// Implementation: replace each `%XX` triple with three spaces in
// the scrub buffer. Three-space replacement preserves the byte
// offsets that the SSH / config-key scrubs and the segment
// splitter rely on (any byte-shifting transform would have to be
// threaded through every later pass). The cost is that we lose
// the ability to detect a malicious agent who URL-encodes a real
// host's dots (`evil%2Eexample%2Ecom`) — but that evasion was
// never caught by the extractor anyway, since `%` already broke
// the label-continuity match. We're not making evasion easier;
// we're closing a benign FP. Double-encoded forms (`%2540`, etc.)
// are themselves `%XX` triples and get scrubbed too.
//
// Case-insensitive on the hex digits because the URL spec
// canonicalizes to uppercase but tools in the wild emit both.
//
// Known limitation: double-encoded forms (`%2540` = `%40` after one
// decode pass) are only partially scrubbed. The outer `%25` blanks
// to spaces, but the residual `40` byte sequence stays — so a
// downstream `40host.com` would still extract as a 2-label host.
// Closing this would require iterating the scrub until no more
// `%XX` patterns appear; we don't because no double-encoded FP has
// surfaced in production reports yet. If one does, add a loop here
// (and a regression test in shell_percent_encoding_test.go's
// "%2540" case).
var percentEncodedRe = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)

// heredocStartRe matches a shell heredoc redirection operator and captures
// its delimiter word: `<<EOF`, `<<-EOF`, `<< 'PY'`, `<<"SQL"`. Group 1 is
// the optional opening quote (unused; RE2 has no backreferences so we don't
// match the closing quote — the delimiter word alone is enough to find the
// body terminator). Group 2 is the delimiter token.
//
// Here-strings (`<<<"text"`) are intentionally not matched: after the first
// `<<` the next char is `<`, not a quote or identifier start, so the
// alternation fails. Bit-shift operators in code (`a << 2`, `cout << endl`)
// are only a heredoc if the consuming command is a language interpreter,
// which processHeredocs verifies before acting — see its doc-comment.
var heredocStartRe = regexp.MustCompile(`<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)`)

// envAssignRe matches a bare shell env-assignment token: `NAME=...`, where
// NAME is a valid shell variable name. Used by segmentLeadingBin to walk past
// a leading run of inline assignments (`PYTHONPATH=src python3 ...`,
// `FOO=bar make ...`) so the real program is classified, mirroring the
// explicit `env KEY=VAL prog` handling. The name-anchored prefix excludes
// flags (`--opt=v` starts with `-`) and paths (`a/b=c` breaks the name
// charset before `=`), so only genuine assignments match.
var envAssignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// nonNetworkBins lists program names whose argument list never carries
// a network endpoint as data. When the leading binary of a shell
// segment is in this set, the per-segment loop in FromShellInDir skips
// the generic urlOrHostRe pass FOR THAT SEGMENT ONLY — other segments
// in the same command (split on |, &&, ||, ;, &) still run normally.
// This closes the false-positive class where dotted config-key tokens
// like `user.email`, `default.region`, `core.account` reach Malanta
// from grep/echo/sed contexts and trigger fail-closed denies.
//
// Trade-offs documented:
//
//   - find . -name '*.com' -exec curl {} \;   suppressed; the agent's
//     actual curl invocation gets its own beforeShellExecution event
//     when the -exec target fires. Same shape as `xargs curl < f`.
//
//   - cat config | curl evil   the cat segment is suppressed, the
//     curl segment runs through extraction, and `evil` extracts. Net
//     effect identical to today's single-pass behavior.
//
// The set is intentionally three-platform: POSIX, cmd.exe natives,
// and PowerShell cmdlets (all keys are lowercased AND post-stripExeExt
// so `Select-String.exe` and `SLS` both hit `select-string`).
var nonNetworkBins = map[string]struct{}{
	// POSIX text + output utilities
	"grep": {}, "egrep": {}, "fgrep": {}, "rg": {}, "ag": {},
	"echo": {}, "printf": {},
	"sed": {}, "awk": {}, "gawk": {}, "mawk": {},
	"cut": {}, "tr": {}, "sort": {}, "uniq": {}, "wc": {},
	"head": {}, "tail": {}, "tee": {},
	"cat": {}, "less": {}, "more": {}, "most": {},
	"find": {}, "xargs": {}, "diff": {}, "cmp": {}, "patch": {},
	// shell test built-ins ([ "$x" = "user.email" ] && ...)
	"test": {}, "[": {},
	// cmd.exe native equivalents
	"findstr": {}, "type": {}, "where": {},
	// PowerShell cmdlets (and short aliases)
	"select-string": {}, "sls": {},
	"get-content": {}, "gc": {},
	"write-host": {}, "write-output": {},
	"out-file": {}, "out-string": {}, "out-host": {}, "out-null": {},
	"sort-object": {}, "where-object": {},
	"foreach-object": {}, "measure-object": {},
	"group-object": {}, "format-table": {}, "format-list": {},
	"set-content": {}, "add-content": {},
}

// nonNetworkGitSubcommands lists `git <subcmd>` invocations whose
// argument list is purely local. Used by isNonNetworkGitSubcommand to
// suppress the generic regex pass for segments led by `git <subcmd>`
// where subcmd is in this set.
//
// `config` is INTENTIONALLY ABSENT: `git config remote.origin.url
// https://github.example/foo.git` legitimately carries a URL VALUE
// that the existing config-key scrub leaves intact and that we want
// extracted. Suppressing the whole git-config segment would regress
// that behavior. The config-key scrub on its own already blanks
// dotted KEY tokens, so `git config user.email yossi@malanta.ai`
// still extracts only `malanta.ai` from the email value.
//
// `clone`, `push`, `pull`, `fetch`, `submodule`, `remote add` are
// ALSO intentionally absent — they are real network operations and
// must run through the verdict cascade like any other curl/wget.
var nonNetworkGitSubcommands = map[string]struct{}{
	"grep": {}, "log": {}, "show": {}, "diff": {},
	"blame": {}, "shortlog": {}, "help": {},
	"rev-parse": {}, "rev-list": {}, "describe": {},
	"status": {}, "stash": {}, "reflog": {}, "bisect": {},
}

// inlineCodeInterpreters maps a non-shell language-interpreter base name to
// the set of flags whose argument is an inline PROGRAM STRING (source code),
// not a script path or a network endpoint. When a shell segment is led by one
// of these interpreters AND carries one of its inline-code flags, the
// segment body is source code in a language where `.` is the member-access
// operator — so dotted tokens like `yaml.safe`, `x.id`, `record.name`,
// `resp.data`, `f.read` are attribute/method references, NOT hostnames.
//
// Why a plain TLD-validity check is not enough: the modern gTLD expansion
// delegated thousands of dictionary-word TLDs (.safe .id .name .data .read
// .app .dev .zip .box .new .run ...). They are real ICANN-managed public
// suffixes, so the publicsuffix check in Normalize accepts them — it cannot
// tell `x.id` (a Python attribute access) from `t.co` (a real host). The
// only reliable signal is CONTEXT: inside language inline code, a dotted
// token is member access unless it carries explicit URL syntax.
//
// For these segments we therefore require explicit URL shape (scheme,
// userinfo, or path — see extractHostsRequireURLShape) before promoting a
// regex match to a domain candidate. A genuine network call inside inline
// code carries a URL ("http://...", urllib / requests / fetch with a
// scheme), so the real deny path (exfil / download to a hostile host) is
// preserved while the member-access false-positive class is suppressed.
//
// SHELL interpreters (bash/sh/zsh -c) are deliberately EXCLUDED: their
// inline body is a shell command line where bare hosts are first-class
// arguments (`bash -c "curl evil.com"`), so they keep the permissive
// extractHosts pass and `ping example.com` inside `bash -c` still extracts.
//
// Known limitation: a bare host smuggled through a nested shell call from
// inside language inline code (`python -c "os.system('curl evil.com')"`)
// is no longer extracted at this hook, because the OS-spawned child does
// not generate its own beforeShellExecution event. This is the same
// tripwire-vs-enforcement trade-off the read-file script-content path
// already accepts (see extractHostsRequireURLShape and AGENTS.md):
// URL-bearing exfils — the overwhelmingly common shape — are still caught.
var inlineCodeInterpreters = map[string]map[string]struct{}{
	"python":     {"-c": {}},
	"python2":    {"-c": {}},
	"python3":    {"-c": {}},
	"node":       {"-e": {}, "--eval": {}, "-p": {}, "--print": {}},
	"nodejs":     {"-e": {}, "--eval": {}, "-p": {}, "--print": {}},
	"bun":        {"-e": {}, "--eval": {}},
	"ruby":       {"-e": {}},
	"perl":       {"-e": {}, "-E": {}},
	"php":        {"-r": {}},
	"lua":        {"-e": {}},
	"pwsh":       {"-c": {}, "-command": {}},
	"powershell": {"-c": {}, "-command": {}},
}

// segmentIsInlineLangCode reports whether a shell segment invokes a non-shell
// language interpreter with an inline-code flag (python -c, node -e, ruby -e,
// perl -e, php -r, pwsh -Command, ...). The leading program is resolved with
// the same prefix-modifier walk as segmentLeadingBin so `sudo python3 -c ...`
// and `env FOO=1 python3 -c ...` are still recognized. See
// inlineCodeInterpreters for the full rationale and trade-offs.
func segmentIsInlineLangCode(seg string) bool {
	head := segmentLeadingBin(seg)
	flags, ok := inlineCodeInterpreters[head]
	if !ok {
		return false
	}
	for _, t := range tokenize(seg) {
		if _, isFlag := flags[strings.ToLower(t)]; isFlag {
			return true
		}
	}
	return false
}

// heredocConsumerIsLangInterp reports whether the command text preceding a
// heredoc operator on the same line resolves to a non-shell language
// interpreter (python/ruby/node/perl/php/...). The text is split on shell
// separators so a leading `cd /x &&` or a pipe is walked past and only the
// command that actually consumes the heredoc is classified
// (`cd /x && python3 - <<'PY'` -> python3). Shell interpreters (bash/sh)
// are NOT in inlineCodeInterpreters, so `bash <<'EOF'` returns false and
// its body keeps the permissive pass.
func heredocConsumerIsLangInterp(preText string) bool {
	segs := splitSegments(preText)
	if len(segs) == 0 {
		return false
	}
	head := segmentLeadingBin(segs[len(segs)-1])
	_, ok := inlineCodeInterpreters[head]
	return ok
}

// heredocWritesSourceFile reports whether the heredoc start line writes its
// body into a NON-shell source file. It scans every token on the line for a
// non-shell source extension, covering all the common writers without
// special-casing each: `cat > foo.py <<'PY'` (redirect), `tee handler.js
// <<'JS'` (filename argument), and `dd of=out.rb <<'RB'` (of= argument). Such
// a body is source code being written to disk, so its dotted member-access
// tokens (`subprocess.run`, `resp.data`) must not be mistaken for hosts.
//
// Shell-script and data-file targets (`> foo.sh`, `> notes.txt`) are NOT
// matched: bare hosts there are first-class, and a shell script's own later
// execution re-extracts via script-follow. The heredoc delimiter token
// (`<<'PY'`) carries no extension, so it never trips this.
func heredocWritesSourceFile(line string) bool {
	for _, tok := range strings.Fields(line) {
		// Strip leading redirect/fd punctuation (`>`, `>>`, `2>`, `|`, ...)
		// and surrounding quotes so a bare `>foo.py` or `'foo.py'` resolves.
		t := strings.Trim(strings.TrimLeft(tok, "<>|&;0123456789"), `'"`)
		if t == "" {
			continue
		}
		if _, ok := nonShellSourceExtensions[strings.ToLower(filepath.Ext(t))]; ok {
			return true
		}
	}
	return false
}

// processHeredocs finds heredoc bodies in a shell command and, for each one
// that is source code — either fed to a non-shell language interpreter
// (`python3 - <<'PY'`, `ruby <<RB`, ...) or written into a non-shell source
// file (`cat > foo.py <<'PY'`, `tee h.js <<'JS'`) — extracts hosts from the
// body with URL shape required and blanks the body lines out of the command.
// It returns the cleaned command (source bodies replaced by empty lines) and
// the hosts found in those bodies.
//
// Rationale: a heredoc fed to a language interpreter is source code, where a
// dotted token (`m.domains`, `x.id`, `resp.data`) is member access, not a
// hostname — but the right-hand labels are real ICANN gTLDs/ccTLDs, so the
// publicsuffix check in Normalize cannot reject them (see
// inlineCodeInterpreters). Worse, splitSegments deliberately splits on
// unquoted newlines, so the per-segment loop would otherwise process each
// code line independently with the permissive extractor and lose the
// interpreter context entirely. Handling the heredoc as one unit here, ahead
// of segmentation, is the only place the "this whole block is Python" signal
// is still available. URL-bearing calls inside the body (a real
// `urlopen('http://...')`) still carry a scheme and are extracted.
//
// Shell-fed heredocs (`bash <<EOF`) and heredocs written to data/shell files
// (`cat <<EOF >notes.txt`, `cat > setup.sh <<EOF`) are left intact: bare hosts
// in a shell body or a host-list file are first-class and must still extract,
// and a shell script's own later execution re-extracts via script-follow.
//
// Bounded and best-effort: a heredoc with no closing delimiter (truncated
// payload) treats the remainder of the command as its body. A `<<` that is
// actually a bit-shift in code is ignored unless its line's pre-`<<` text
// classifies as a language interpreter, which arithmetic never does.
func processHeredocs(command string) (string, []string) {
	if !strings.Contains(command, "<<") {
		return command, nil
	}
	lines := strings.Split(command, "\n")
	var hosts []string
	i := 0
	for i < len(lines) {
		loc := heredocStartRe.FindStringSubmatchIndex(lines[i])
		if loc == nil {
			i++
			continue
		}
		delim := lines[i][loc[4]:loc[5]]
		// A heredoc body is source code (URL shape required) when it is
		// either fed to a language interpreter (`python3 - <<'PY'`) or
		// written into a non-shell source file (`cat > foo.py <<'PY'`).
		isLang := heredocConsumerIsLangInterp(lines[i][:loc[0]]) ||
			heredocWritesSourceFile(lines[i])

		// Body runs from the next line up to (but not including) the
		// line whose trimmed content is exactly the delimiter. TrimSpace
		// also covers the `<<-` leading-tab-stripping variant.
		bodyStart := i + 1
		j := bodyStart
		for j < len(lines) && strings.TrimSpace(lines[j]) != delim {
			j++
		}
		if isLang {
			body := strings.Join(lines[bodyStart:j], "\n")
			hosts = append(hosts, extractHostsRequireURLShape(body)...)
			for k := bodyStart; k < j; k++ {
				lines[k] = ""
			}
			debugLog("layer1: heredoc body (delim=%q) fed to interpreter; requiring URL shape", delim)
		}
		// Resume scanning after the closing delimiter line (or at EOF).
		if j < len(lines) {
			i = j + 1
		} else {
			i = j
		}
	}
	return strings.Join(lines, "\n"), hosts
}

// FromShell returns the set of public hostnames referenced by a shell command.
// command may be the full command line (single string) or already split argv;
// both forms are tolerated by walking through whitespace-separated tokens
// after stripping common quoting.
//
// This is FromShellInDir with no cwd context. Production callers should
// prefer FromShellInDir so relative script paths can be resolved correctly;
// FromShell exists for tests and any caller that genuinely has no cwd.
func FromShell(command string) []string {
	return FromShellInDir(command, "")
}

// FromShellInDir is FromShell but also follows local script invocations
// ("./X.sh", "bash X.sh", "python X.py", ...) by reading the script body
// (capped at maxScriptBytes) and running it through the same extractHosts
// pipeline. This is the defense against the "innocuous-command, malicious
// script body" attack class: pre-execution hooks can only see the command
// they're authorizing, so if the bad domain is inside a script the command
// merely invokes, no scanning of the command alone will catch it.
//
// `cwd` is used to resolve relative script paths against the agent's
// working directory at the time of the hook event. Pass "" to fall back to
// the hook process's own cwd (whatever Cursor set when spawning us).
//
// Script following is bounded:
//   - file size cap (maxScriptBytes)
//   - recursion depth = 1 (a script that itself invokes another script
//     gets its own beforeShellExecution event when actually executed; we
//     don't chase the chain at extract time)
//   - failures (missing file, oversize, unreadable) silently produce no
//     extra domains; the rest of FromShell still runs.
func FromShellInDir(command, cwd string) []string {
	return fromShellInDirWithDepth(command, cwd, 0)
}

// fromShellInDirWithDepth is the internal worker behind FromShellInDir.
// `depth` is the script-follow recursion depth: 0 for the top-level
// command Cursor handed us, 1 for a script body that the top-level
// command is about to invoke. Anything beyond 1 is the "script-chain
// follow" case which we deliberately do NOT chase (per
// AGENTS.md: "a script that itself invokes another script gets
// its own beforeShellExecution event when actually executed"), so
// step 4 is guarded by `depth < 1`.
//
// All steps OTHER than script-follow are identical at every depth:
// SSH scrub, config-key scrubs, per-segment regex with suppression,
// and per-tool extractors all run on the script body too. Before the
// Phase B.2 fix, script-body scanning called extractHosts(body)
// directly, which bypassed the scrubs and the segment loop and
// caused the dotted-config-key FP class (`user.email`,
// `default.region`, ...) to resurface from script bodies that the
// per-command extraction already learned to suppress.
func fromShellInDirWithDepth(command, cwd string, depth int) []string {
	if command == "" {
		return nil
	}
	out := make([]string, 0, 4)

	// 0. Heredoc bodies that are source code — fed to a language interpreter
	//    (`python3 - <<'PY'`) or written into a non-shell source file
	//    (`cat > foo.py <<'PY'`) — are extracted with URL shape required and
	//    blanked out of the command BEFORE the per-segment loop runs:
	//    splitSegments splits on unquoted newlines and would otherwise
	//    process each code line permissively, false-positiving on
	//    member-access tokens (`subprocess.run`, `x.id`, ...) whose
	//    right-hand labels are real gTLDs. Shell-fed heredocs and data-file
	//    heredocs are left intact so bare hosts there still extract. See
	//    processHeredocs.
	command, heredocHosts := processHeredocs(command)
	out = append(out, heredocHosts...)

	// 1. scp-style git@host:path URLs. Capture the host AND blank out the full
	//    match so step 2's generic regex doesn't re-interpret the path tail
	//    ("org/repo.git") as a separate hostname.
	scrub := []byte(command)
	for _, m := range gitSSHRe.FindAllStringSubmatchIndex(command, -1) {
		if len(m) >= 6 {
			if host := Normalize(command[m[4]:m[5]]); host != "" {
				out = append(out, host)
			}
			for i := m[0]; i < m[1]; i++ {
				scrub[i] = ' '
			}
		}
	}

	// 1b. CLI config-key tokens (git config user.email, aws configure set
	//     default.region, etc.). The KEY arg of these subcommands often has
	//     a TLD-shaped suffix (.email / .name / .editor / .region / .project
	//     are all real ICANN TLDs on the PSL) that step 2's generic regex
	//     would otherwise extract and feed to Malanta, which then labels the
	//     config-key as Suspicius and fail-closed denies the whole command.
	//     Scrubbing the KEY byte range here keeps Normalize from ever seeing
	//     it. The VALUE arg (if present) is intentionally NOT scrubbed —
	//     values legitimately contain URLs (e.g. `git config
	//     remote.origin.url https://example.com/foo.git`).
	//
	//     We operate on `scrub` (already SSH-scrubbed) rather than the
	//     original `command`, so successive scrubs compose.
	for _, re := range configKeyScrubREs {
		for _, m := range re.FindAllSubmatchIndex(scrub, -1) {
			if len(m) >= 4 {
				for i := m[2]; i < m[3]; i++ {
					scrub[i] = ' '
				}
			}
		}
	}

	// 1c. URL-percent-encoded byte sequences. Blank out every `%XX`
	//     triple so the generic regex doesn't slide forward past `%`
	//     and pick up an accidental host from the hex digits + the
	//     real host that follows it. The canonical case is a
	//     `?email=user%40host.tld` query parameter where the encoded
	//     `@` left `40host.tld` exposed to the host alternation. See
	//     percentEncodedRe doc-comment for the full rationale + the
	//     trade-off vs. URL-encoded-dot evasion (`evil%2Eexample`).
	for _, m := range percentEncodedRe.FindAllIndex(scrub, -1) {
		for i := m[0]; i < m[1]; i++ {
			scrub[i] = ' '
		}
	}
	scrubbed := string(scrub)

	// 2. Generic URL/host regex pass over the (scrubbed) command line —
	//    now per-segment, so a non-network leading binary (grep, echo,
	//    sed, Get-Content, ...) suppresses extraction within its own
	//    segment only. Other segments of the same command — joined by
	//    |, &&, ||, ;, or & — still extract normally. This is the
	//    structural fix for the dotted-config-key FP class
	//    (`user.email`, `default.region`, ...). See AGENTS.md for
	//    context.
	for _, seg := range splitSegments(scrubbed) {
		head := segmentLeadingBin(seg)
		if _, suppressed := nonNetworkBins[head]; suppressed {
			debugLog("layer1: suppressed segment %q (head=%q)", seg, head)
			continue
		}
		if isNonNetworkGitSubcommand(seg) {
			debugLog("layer1: suppressed segment %q (git non-network subcommand)", seg)
			continue
		}
		if segmentIsInlineLangCode(seg) {
			// Inline language code (python -c, node -e, ...): require
			// explicit URL shape so member-access expressions like
			// `yaml.safe` / `x.id` are not mistaken for hostnames on
			// dictionary-word gTLDs. See inlineCodeInterpreters.
			debugLog("layer1: inline-code segment %q (head=%q); requiring URL shape", seg, head)
			out = append(out, extractHostsRequireURLShape(seg)...)
			continue
		}
		out = append(out, extractHosts(seg)...)
	}

	// 3. Per-tool extractors for cases where the host is buried in a flag value.
	tokens := tokenize(command)
	if len(tokens) > 0 {
		bin := stripExeExt(strings.ToLower(lastPathComponent(tokens[0])))
		switch bin {
		case "pip", "pip3", "uv", "poetry":
			out = append(out, fromPipArgs(tokens[1:])...)
		case "npm", "pnpm", "yarn":
			out = append(out, fromNPMArgs(tokens[1:])...)
		case "docker", "podman":
			out = append(out, fromDockerArgs(tokens[1:])...)
		case "helm":
			out = append(out, fromHelmArgs(tokens[1:])...)
		case "kubectl":
			out = append(out, fromKubectlArgs(tokens[1:])...)
		case "ssh", "scp", "rsync":
			out = append(out, fromSSHFamilyArgs(tokens[1:])...)
		case "ping", "traceroute", "tracepath", "mtr", "tracert",
			"nslookup", "dig", "host", "drill", "resolve-dnsname",
			"whois", "nc", "netcat", "ncat", "telnet",
			"test-netconnection", "tnc", "test-connection":
			out = append(out, fromNetworkDiagArgs(tokens[1:])...)
		}
	}

	// 4. Script-invocation follow: if the command runs a local script,
	//    scan the script body too. Bounded at depth 1 — a script that
	//    itself invokes another script gets its own beforeShellExecution
	//    event when actually executed; we don't chase the chain at
	//    extract time.
	if depth < 1 {
		for _, sp := range scriptInvocationPaths(tokens) {
			out = append(out, fromScriptFile(sp, cwd)...)
		}
		// 5. Manifest follow: an install command names its own dependency
		//    manifest in argv, and that command IS the action the file only
		//    recorded. Same depth cap as script-following.
		for _, mp := range manifestFollowPaths(tokens) {
			out = append(out, fromManifestFile(mp, cwd)...)
		}
	}

	return Dedup(out)
}

// GitHubFromShell is GitHubFromShellInDir with no cwd context, for tests
// and callers that genuinely have no working directory.
func GitHubFromShell(command string) GitHubRefs {
	return GitHubFromShellInDir(command, "")
}

// GitHubFromShellInDir extracts GitHub repository/owner identities from a
// shell command and from the body of any local script the command invokes,
// mirroring FromShellInDir's script-follow so the "innocuous command,
// malicious script body" class is covered for repositories too (a
// `./setup.sh` that clones a flagged repository).
//
// It scans the RAW command text rather than the scrubbed, per-segment form
// the host extractor builds. Those defenses all exist to stop a non-host
// token from being mistaken for a hostname — a dotted config key, a
// member-access expression, a percent-encoded byte — and none of that
// ambiguity exists here: every form this recognizes is self-identifying
// (a GitHub host, a "github:" prefix, or a `uses:` step), so there is
// nothing for the scrubs to protect against and applying them would only
// blank out references the command really does make.
//
// Script following is bounded exactly as FromShellInDir's is: one level
// deep, capped at maxScriptBytes, with every read failure absorbed
// silently.
func GitHubFromShellInDir(command, cwd string) GitHubRefs {
	if command == "" {
		return GitHubRefs{}
	}
	var a githubAcc
	a.scan(command)
	tokens := tokenize(command)
	for _, sp := range scriptInvocationPaths(tokens) {
		if body, _, ok := readFollowedFile(sp, cwd); ok {
			a.scan(body)
		}
	}
	// A dependency manifest can point a dependency straight at a
	// repository (`git+https://github.com/owner/repo@ref` in a
	// requirements file, a `git = "..."` key in Cargo.toml). The install
	// command that consumes the manifest is the action; the file is only
	// the record, so this is where that reference gets checked.
	for _, mp := range manifestFollowPaths(tokens) {
		if body, _, ok := readFollowedFile(mp, cwd); ok {
			a.scan(body)
		}
	}
	return a.refs()
}

// manifestFollowPaths returns dependency-manifest paths named by flags in
// the given tokenized command — see manifestFlagsByTool for which flags,
// and why following them at execution time is the right checkpoint.
//
// Both `--flag value` and `--flag=value` forms are handled. `python -m pip
// install -r X` is recognized by skipping the interpreter prefix, since
// that is how pip is invoked in most CI and venv-less setups.
//
// A requirements file may itself contain `-r nested.txt`. That nesting is
// deliberately NOT chased, matching the script-follow depth cap: one level
// only, so a cycle or a deep chain can't burn the hook budget.
func manifestFollowPaths(tokens []string) []string {
	if len(tokens) == 0 {
		return nil
	}
	rest := tokens
	// `python -m pip ...` / `python3 -m pip ...`: step over the
	// interpreter so the tool lookup below sees "pip".
	if _, isLang := langInterpreters[strings.ToLower(lastPathComponent(tokens[0]))]; isLang {
		for i := 1; i+1 < len(tokens); i++ {
			if tokens[i] == "-m" {
				rest = tokens[i+1:]
				break
			}
		}
	}
	flags, known := manifestFlagsByTool[strings.ToLower(lastPathComponent(rest[0]))]
	if !known {
		return nil
	}
	var out []string
	for i := 1; i < len(rest); i++ {
		tok := rest[i]
		if eq := strings.IndexByte(tok, '='); eq > 0 {
			if _, ok := flags[tok[:eq]]; ok {
				if v := tok[eq+1:]; v != "" {
					out = append(out, v)
				}
			}
			continue
		}
		if _, ok := flags[tok]; ok && i+1 < len(rest) {
			if v := rest[i+1]; v != "" && !strings.HasPrefix(v, "-") {
				out = append(out, v)
				i++
			}
		}
	}
	return out
}

// fromManifestFile reads a followed dependency manifest and extracts hosts
// from it with the PERMISSIVE extractor, not the URL-shape-required one
// used for source scripts: a bare registry hostname is first-class syntax
// in these formats (`--index-url`, a `.npmrc` line, a Gemfile `source`),
// so requiring URL shape would drop exactly the hijacked-registry signal
// worth having. Every read failure is absorbed silently, as with
// script-following.
func fromManifestFile(path, cwd string) []string {
	body, _, ok := readFollowedFile(path, cwd)
	if !ok {
		return nil
	}
	return extractHosts(body)
}

// scriptInvocationPaths returns local script paths referenced by the given
// tokenized command. Two patterns are recognized:
//
//  1. interpreter + script:  "bash X.sh", "python -u X.py", "node X.js"
//  2. direct invocation:     "./X.sh", "/abs/path/X.sh", "scripts/foo.py"
//
// `bash -c "<inline>"` is intentionally excluded - the inline command is
// already on the command line and gets the generic regex pass; trying to
// open it as a file is a guaranteed stat failure that wastes hook budget.
func scriptInvocationPaths(tokens []string) []string {
	if len(tokens) == 0 {
		return nil
	}
	head := strings.ToLower(lastPathComponent(tokens[0]))

	if _, isShell := shellInterpreters[head]; isShell {
		return scriptArgAfterFlags(tokens[1:], true /*shell-style flags*/)
	}
	if _, isLang := langInterpreters[head]; isLang {
		return scriptArgAfterFlags(tokens[1:], false)
	}
	if looksLikeLocalScript(tokens[0]) {
		return []string{tokens[0]}
	}
	return nil
}

// scriptArgAfterFlags walks forward past flag-shaped tokens and returns the
// first concrete script argument (as a single-element slice). It bails out
// on `-c`/`-`/`--` which indicate inline commands, stdin, or end-of-flags
// without a following script.
//
// `shellStyleFlags` reflects that POSIX shells like bash accept `-c <cmd>`
// for an inline command; language interpreters use the same convention for
// python/ruby/perl but not consistently for node, so we accept either way.
func scriptArgAfterFlags(rest []string, shellStyleFlags bool) []string {
	_ = shellStyleFlags // semantically identical handling today; named arg
	// preserved for future per-interpreter divergence.
	for i := 0; i < len(rest); i++ {
		t := rest[i]
		if t == "-c" || t == "/c" || t == "-" || t == "--" {
			return nil
		}
		if strings.HasPrefix(t, "-") {
			continue
		}
		return []string{t}
	}
	return nil
}

// looksLikeLocalScript matches tokens that look like a path-to-a-script:
// "./foo.sh", "../foo.sh", "/abs/path/foo.sh", "scripts/foo.py". Bare binary
// names ("bash", "curl") are NOT matched; those are tools, not scripts.
func looksLikeLocalScript(tok string) bool {
	if tok == "" {
		return false
	}
	ext := strings.ToLower(filepath.Ext(tok))
	if _, ok := scriptExtensions[ext]; ok {
		return true
	}
	// No recognized extension: only follow if the token has an explicit
	// path prefix that screams "execute this file". Plain "foo/bar" tokens
	// are usually just paths mentioned in ls/find/etc., not invocations.
	return strings.HasPrefix(tok, "./") ||
		strings.HasPrefix(tok, "../") ||
		strings.HasPrefix(tok, "/")
}

// fromScriptFile reads up to maxScriptBytes of a candidate script and runs
// the generic extractHosts pipeline over its body. Any error (missing file,
// directory, oversize, unreadable) is silently absorbed and produces no
// extra domains - the script-follow is strictly best-effort and must not
// derail the rest of FromShell.
//
// Relative paths are resolved against `cwd` when provided; otherwise the
// OS-level cwd of the hook process is used.
func fromScriptFile(path, cwd string) []string {
	body, resolved, ok := readFollowedFile(path, cwd)
	if !ok {
		return nil
	}
	// Non-shell source scripts (.py/.js/.rb/...) are programming-language
	// code where `.` is member access. Run them through the URL-shape-
	// required extractor so attribute references (subprocess.run, resp.data)
	// are not mistaken for hosts on dictionary-word gTLDs, while real
	// network literals (urlopen("https://evil.com")) still extract. This
	// matches the read-file hook's per-content-shape routing and the
	// inline-code / heredoc guards.
	if _, ok := nonShellSourceExtensions[strings.ToLower(filepath.Ext(resolved))]; ok {
		return extractHostsRequireURLShape(body)
	}
	// Shell scripts (and ambiguous ./bin invocations) run through the FULL
	// shell pipeline (config-key scrubs + per-segment suppression + per-tool
	// extractors), bounded at recursion depth 1 so a nested script
	// invocation in the body is not chased here. We pass the script's own
	// directory as the cwd so any further relative-path references inside the
	// body resolve the same way bash would at execution time.
	return fromShellInDirWithDepth(body, filepath.Dir(resolved), 1)
}

// readFollowedFile reads up to maxScriptBytes of a file the command is
// about to consume — a script body, or a dependency manifest named by an
// install flag — applying the guards described below. It returns
// the body and the resolved absolute-or-cwd-relative path; ok is false for
// every failure mode (missing, non-regular, oversize, unreadable), all of
// which callers absorb silently: following is strictly best-effort and must
// never derail the extraction it augments.
//
// Shared by the host extractor and the GitHub extractor so a followed file
// is subject to exactly one set of guards. The second read is served from
// the page cache, which is cheaper than threading two result types through
// the whole shell pipeline.
func readFollowedFile(path, cwd string) (body, resolved string, ok bool) {
	if path == "" {
		return "", "", false
	}
	resolved = path
	if !filepath.IsAbs(path) && cwd != "" {
		resolved = filepath.Join(cwd, path)
	}
	// Require a REGULAR file and bound the read.
	//  - Lstat (not Stat): a symlink is not silently followed to a special
	//    file or outside the tree; only a plain regular file is followed.
	//  - Reject non-regular (directory, FIFO, device, socket, symlink):
	//    reading a FIFO or device would BLOCK the hook until Cursor's
	//    timeout, turning a benign command into a fail-closed denial.
	//  - Size cap from the same stat.
	li, err := os.Lstat(resolved)
	if err != nil || !li.Mode().IsRegular() || li.Size() > maxScriptBytes {
		return "", "", false
	}
	f, err := os.Open(resolved)
	if err != nil {
		return "", "", false
	}
	defer func() { _ = f.Close() }()
	// Re-check on the OPEN descriptor to shrink the Lstat->Open TOCTOU
	// window: if the path was swapped for a non-regular file after Lstat,
	// the fd's own stat catches it before we read. (Residual: on the rare
	// swap-to-FIFO that wins the race, os.Open itself could block until the
	// hook timeout on non-Windows; a fully non-blocking open would need
	// platform-specific O_NONBLOCK, deferred as it isn't portable to the
	// Windows build. The regular-file guard closes the common planted-FIFO
	// case.)
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return "", "", false
	}
	// Bounded read regardless of what stat reported: io.LimitReader caps the
	// bytes even if the file grew between Lstat and read.
	data, err := io.ReadAll(io.LimitReader(f, maxScriptBytes))
	if err != nil {
		return "", "", false
	}
	return string(data), resolved, true
}

// tokenize is a minimal shell-aware splitter. It does NOT honor full POSIX
// quoting rules (which would require a real parser); it handles the cases we
// see in practice (simple quoted strings, no command substitution).
func tokenize(cmd string) []string {
	var out []string
	var b strings.Builder
	var quote rune = 0
	for _, r := range cmd {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t' || r == '\n':
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func lastPathComponent(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// exeExts is the set of executable-suffix variants stripExeExt removes.
// Windows uses these on every binary invocation, so a Cursor hook payload
// containing `curl.exe`, `docker.exe`, or `Get-Content.ps1` reaches the
// per-tool dispatch and the nonNetworkBins / networkBins lookups with a
// suffix that the lowercased POSIX-shaped sets don't include. Stripping
// once at the lookup site lets one set definition serve all three
// target platforms (macOS, Linux, Windows).
//
// `.com` is included because cmd.exe will run a foo.com binary as an
// executable in the same way as foo.exe; the suffix-strip is idempotent
// on POSIX where this convention doesn't exist.
var exeExts = []string{".exe", ".com", ".cmd", ".bat", ".ps1", ".psm1"}

// stripExeExt removes a single trailing Windows-executable suffix from
// s, lowercased. Returns s unchanged if no recognized suffix is present.
// Caller is expected to have already lowercased s via strings.ToLower.
func stripExeExt(s string) string {
	for _, ext := range exeExts {
		if strings.HasSuffix(s, ext) {
			return s[:len(s)-len(ext)]
		}
	}
	return s
}

// splitSegments returns substrings of cmd separated by unquoted shell
// statement terminators: the chain operators (|, &&, ||, ;, &) AND
// unquoted newlines (\n, \r). The returned slices are trimmed of
// surrounding whitespace; empty results are dropped. Quoted strings
// (single or double) are NOT split — so `echo "a && b"` and
// `echo "line1\nline2"` each stay as one segment, matching shell
// semantics. Segments whose first non-whitespace character is `#`
// are bash comment lines and are dropped entirely (see flush()).
//
// Newlines are treated as separators because a real multi-line bash
// script ($'cmd1\ncmd2\n') is two statements, and Cursor hands the
// whole script to the hook as a single command string. Without
// newline splitting, the per-segment non-network-binary suppression
// in step 2 of FromShellInDir collapses cross-line statements into
// one giant segment, defeating the suppression for any line whose
// leading bin happens to not be in nonNetworkBins (e.g. a pipe RHS
// like `... | /path/to/some-helper`). Quoted newlines are still
// preserved as part of the segment, so a string argument containing
// a literal "\n" is not over-split. CRLF is handled by treating \r
// the same as \n (the resulting empty segment from a bare \r\n is
// dropped by the empty-segment filter in flush()).
//
// This is NOT a real shell parser. Heredocs, command substitution,
// backslash-newline line continuation, and nested quoting are
// intentionally not handled. When in doubt the splitter chooses to
// over-split: an under-split would silently merge a benign and a
// suspicious statement into one segment and might suppress
// extraction for the suspicious half, weakening defense. An
// over-split costs at most a redundant extractHosts pass on a
// fragment, which is cheap and safe.
//
// Why byte-level iteration: all chain operators, quote characters,
// and line separators are single-byte ASCII, and any UTF-8 multibyte
// sequence inside a host argument has its bytes copied through
// unchanged. So byte-level is correct without paying the rune-decode
// cost on the hot path.
func splitSegments(cmd string) []string {
	var segs []string
	var b strings.Builder
	var quote byte = 0
	flush := func() {
		s := strings.TrimSpace(b.String())
		// Drop bash comment lines: any segment whose first
		// non-whitespace character is `#` is shell-comment text
		// that bash itself never executes. Real-world multi-line
		// scripts authored by humans or LLM agents routinely
		// carry "# note about <dotted.key>" lines that, before
		// this filter, were extracted by the generic regex pass
		// and tripped Suspicius denies. NOTE: this drops ONLY
		// comment-led segments — a TRAILING comment on a real
		// statement (`cmd args # comment`) is still part of its
		// segment and not stripped. Trailing-comment stripping
		// would require token-boundary tracking through quotes;
		// it's a known limitation logged for follow-up rather
		// than tackled inline here.
		if s != "" && s[0] != '#' {
			segs = append(segs, s)
		}
		b.Reset()
	}
	for i := 0; i < len(cmd); {
		c := cmd[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			b.WriteByte(c)
			i++
		case c == '\'' || c == '"':
			quote = c
			b.WriteByte(c)
			i++
		case c == '|' && i+1 < len(cmd) && cmd[i+1] == '|':
			flush()
			i += 2
		case c == '&' && i+1 < len(cmd) && cmd[i+1] == '&':
			flush()
			i += 2
		case c == '|' || c == ';' || c == '&' || c == '\n' || c == '\r':
			flush()
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	flush()
	return segs
}

// prefixModifiers names tokens that wrap a real program rather than
// being a real program themselves. When segmentLeadingBin sees one of
// these as the head of a segment, it walks past it (and any of its
// flags) to classify the *underlying* program. Without this, common
// shell idioms like `sudo grep user.email /etc/foo` or
// `nice -n 10 sed -i 's/foo/bar/' file` would classify as `sudo` /
// `nice` (neither in nonNetworkBins) and the segment would not be
// suppressed.
var prefixModifiers = map[string]struct{}{
	"sudo": {}, "doas": {}, "nice": {}, "ionice": {},
	"time": {}, "command": {}, "exec": {}, "builtin": {},
	"nohup": {}, "taskset": {}, "chrt": {},
	"&": {}, // PowerShell call operator: `& "C:\Path\foo.exe" args...`
}

// segmentLeadingBin returns the lowercased, exe-stripped basename of
// the first non-prefix-modifier token in seg, ready for membership
// lookups against nonNetworkBins / networkBins.
//
// Walk-past handling:
//
//   - Tokens in prefixModifiers are consumed; we keep advancing to find
//     the actual program.
//   - After consuming a modifier, we skip subsequent flag-shaped tokens
//     so that `nice -n 10 sed x` resolves to `sed`, not `-n`. Short
//     single-letter flags (`-n`, `-c`, `-X`) are presumed to take a
//     separate-token value: the token following the flag is also
//     skipped, unless it itself starts with `-`. Long flags (`--name`,
//     `--name=value`) are skipped on their own.
//   - Bare `NAME=VALUE ... prog` inline env-assignment prefixes are
//     skipped (`PYTHONPATH=src python3 -c ...`, `FOO=bar make ...`). This
//     is the shell form without an explicit `env`; without it the leading
//     bin classifies as `pythonpath=src` and the inline-code / suppression
//     logic that keys off the real interpreter never fires.
//   - `env KEY=VAL ... prog` walks past the env-vars block until the
//     first token without `=` (and without `/`, to avoid mistaking a
//     path containing `=` for an env-var assignment).
//
// Returns "" for empty or all-modifier segments.
func segmentLeadingBin(seg string) string {
	toks := tokenize(seg)
	i := 0
	for i < len(toks) {
		// Walk past a leading run of bare shell env assignments.
		if envAssignRe.MatchString(toks[i]) {
			i++
			continue
		}
		t := stripExeExt(strings.ToLower(lastPathComponent(toks[i])))
		if _, isMod := prefixModifiers[t]; isMod {
			i++
			// Skip flags belonging to the modifier. Short flags (`-X`)
			// presumed to take a value: also skip the following token.
			for i < len(toks) && strings.HasPrefix(toks[i], "-") {
				flag := toks[i]
				i++
				if len(flag) == 2 && i < len(toks) && !strings.HasPrefix(toks[i], "-") {
					i++
				}
			}
			continue
		}
		if t == "env" {
			i++
			for i < len(toks) {
				if strings.Contains(toks[i], "=") && !strings.ContainsAny(toks[i], "/\\") {
					i++
					continue
				}
				return stripExeExt(strings.ToLower(lastPathComponent(toks[i])))
			}
			return ""
		}
		return t
	}
	return ""
}

// isNonNetworkGitSubcommand returns true if seg's leading binary (post
// walk-past) is `git` AND the first non-flag argument is in
// nonNetworkGitSubcommands. `git -C /repo log --grep=...`,
// `git --no-pager grep foo`, and similar global-flag-prefixed
// invocations are handled by walking past flag tokens; the helper
// `-C` and `-c` flags consume the following argument as their value
// before resuming the subcommand search.
func isNonNetworkGitSubcommand(seg string) bool {
	toks := tokenize(seg)
	if len(toks) < 2 {
		return false
	}
	head := stripExeExt(strings.ToLower(lastPathComponent(toks[0])))
	if head != "git" {
		return false
	}
	for i := 1; i < len(toks); i++ {
		t := toks[i]
		if strings.HasPrefix(t, "-") {
			if t == "-C" || t == "-c" {
				i++ // value-taking flag; consume next token
			}
			continue
		}
		_, ok := nonNetworkGitSubcommands[strings.ToLower(t)]
		return ok
	}
	return false
}

// debugLog writes a single stderr line when TRUSTGATE_HOOKS_DEBUG is set
// in the process env. Cursor surfaces hook stderr in its hook-output
// panel, so this is the operator-visible diagnostic channel for "why
// did extraction skip this command?". Disabled by default; the env
// file shipped to customers via MDM does NOT set the variable, so
// production deployments are silent unless an operator opts in for
// local diagnosis.
//
// Cost when disabled: one os.Getenv call per debug site (a handful per
// hook invocation). Cheap relative to the 250 ms hook budget.
func debugLog(format string, args ...any) {
	if os.Getenv("TRUSTGATE_HOOKS_DEBUG") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "[trustgate debug] "+format+"\n", args...)
}

func fromPipArgs(args []string) []string {
	var out []string
	for i, a := range args {
		switch {
		case a == "--index-url" || a == "-i" || a == "--extra-index-url" || a == "--find-links" || a == "-f":
			if i+1 < len(args) {
				if h := NormalizeURL(args[i+1]); h != "" {
					out = append(out, h)
				}
			}
		case strings.HasPrefix(a, "--index-url=") ||
			strings.HasPrefix(a, "--extra-index-url=") ||
			strings.HasPrefix(a, "--find-links="):
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				if h := NormalizeURL(a[eq+1:]); h != "" {
					out = append(out, h)
				}
			}
		}
	}
	return out
}

func fromNPMArgs(args []string) []string {
	var out []string
	for i, a := range args {
		switch {
		case a == "--registry":
			if i+1 < len(args) {
				if h := NormalizeURL(args[i+1]); h != "" {
					out = append(out, h)
				}
			}
		case strings.HasPrefix(a, "--registry="):
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				if h := NormalizeURL(a[eq+1:]); h != "" {
					out = append(out, h)
				}
			}
		}
	}
	return out
}

func fromDockerArgs(args []string) []string {
	// docker pull foo.example/img:tag  -> extract the registry host
	// docker run --pull always foo.example/img -> same
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		// First "/" separates registry from path in image references.
		if i := strings.IndexByte(a, '/'); i > 0 {
			candidate := a[:i]
			if strings.Contains(candidate, ".") || strings.Contains(candidate, ":") {
				// Strip any :tag/digest suffix
				if c := strings.IndexAny(candidate, ":@"); c > 0 {
					candidate = candidate[:c]
				}
				if h := Normalize(candidate); h != "" {
					out = append(out, h)
				}
			}
		}
	}
	return out
}

func fromHelmArgs(args []string) []string {
	var out []string
	for i, a := range args {
		if a == "repo" && i+1 < len(args) && args[i+1] == "add" && i+3 < len(args) {
			if h := NormalizeURL(args[i+3]); h != "" {
				out = append(out, h)
			}
		}
	}
	return out
}

func fromKubectlArgs(args []string) []string {
	var out []string
	for i, a := range args {
		if a == "--server" && i+1 < len(args) {
			if h := NormalizeURL(args[i+1]); h != "" {
				out = append(out, h)
			}
		}
		if strings.HasPrefix(a, "--server=") {
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				if h := NormalizeURL(a[eq+1:]); h != "" {
					out = append(out, h)
				}
			}
		}
	}
	return out
}

func fromSSHFamilyArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		// Only consider tokens that have explicit remote-host context
		// (userinfo "user@host" or scp-style "host:path"). A bare arg like
		// "file.tgz" or "backup.json" is almost certainly a local filename,
		// not a host. Real hostnames in scp/rsync/ssh always carry "@" or ":".
		if !strings.ContainsAny(a, "@:") {
			continue
		}
		host := a
		if at := strings.IndexByte(host, '@'); at >= 0 {
			host = host[at+1:]
		}
		if colon := strings.IndexByte(host, ':'); colon >= 0 {
			host = host[:colon]
		}
		if h := Normalize(host); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// fromNetworkDiagArgs extracts hostnames from network-diagnostic tools
// (ping, dig, host, nslookup, traceroute/tracert, nc, telnet, whois,
// mtr, Test-NetConnection, Resolve-DnsName, ...) where every non-flag
// positional argument is itself a network target.
//
// Unlike fromSSHFamilyArgs we deliberately do NOT require "@" / ":" in
// the token — the whole reason this helper exists is that
// `ping evil.example` is the canonical bare-host invocation and the
// adjacency-context guard in Phase C (Layer 2) would otherwise have to
// special-case the diagnostic tools to keep them working.
//
// Skipped:
//   - tokens starting with "-" or "+"  (POSIX flags, dig "+short" etc.)
//   - tokens starting with "@"          (dig/nslookup resolver: "@192.0.2.8")
//   - all-digit tokens                  (nc/telnet port: `nc host 80`)
//   - Normalize-rejected tokens         (loopback, RFC1918, bare label, …)
//
// PowerShell-style flags use "-Name value" rather than "--name=value",
// but the "-" prefix is the same so the flag-walk works for both.
//
// NOTE on the "@192.0.2.8" case: this helper skips the resolver token,
// but the upstream generic urlOrHostRe pass (step 2 of
// fromShellInDirWithDepth) still extracts "192.0.2.8" because it's a
// perfectly valid public IPv4 and Malanta can answer IPv4 lookups
// (/v1/ips/reputation). The net effect of `dig @192.0.2.8 evil.example`
// is therefore BOTH hosts extracted, not just the target. That's
// intentional: a public-IP resolver is itself useful telemetry (it
// tells you the agent went around the OS resolver), and a clean
// resolver will simply resolve to an allow/low-score verdict. We do
// not paper over the generic-pass extraction here.
func fromNetworkDiagArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+") {
			continue
		}
		if strings.HasPrefix(a, "@") {
			// dig/nslookup resolver — the operator's intent is to query
			// about the target host, not the resolver. Intentionally
			// dropped; if a user really wants a resolver hostname checked
			// they can `ping <resolver>` directly.
			continue
		}
		if isAllDigits(a) {
			continue // nc/telnet port
		}
		if h := Normalize(a); h != "" {
			out = append(out, h)
		}
	}
	return out
}
