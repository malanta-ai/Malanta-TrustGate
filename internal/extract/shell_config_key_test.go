package extract

import (
	"reflect"
	"testing"
)

// These tests cover the CLI config-key scrub introduced to eliminate the
// FP class where `<tool> config <KEY>` arguments like user.email /
// user.name / init.author.email / core.account got extracted as TLD-shaped
// hostnames and (because .email / .name / .account are real ICANN TLDs on
// the PSL) labeled Suspicius by Malanta, causing fail-closed denial of
// every benign `git config` / `gcloud config set` / etc. invocation.
//
// Each tool gets:
//   1. Scrub cases: the KEY token must NOT appear in the extracted host set,
//      even when its rightmost label is on the PSL.
//   2. Key + URL value cases: the KEY is scrubbed but the URL VALUE is
//      still extracted, so `git config remote.origin.url https://...`
//      continues to work as the agent's primary mechanism for routing
//      git through the right remote.
//
// A trailing regression block guards the well-trodden non-config invocations
// (git clone, kubectl apply -f <URL>, curl, plain `npm install`) so the new
// scrub doesn't accidentally suppress real hostnames.

// TestFromShell_ConfigKeyScrub is table-driven across all five in-scope tools.
// The case names embed the FP-prone TLD suffix so a failure points straight
// at which subcommand variant regressed.
func TestFromShell_ConfigKeyScrub(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		// --- git config -----------------------------------------------------
		{
			name:    "git config user.email + value email-shaped",
			command: "git config user.email yossi@malanta.ai",
			want:    []string{"malanta.ai"},
		},
		{
			name:    "git config user.name with quoted display name",
			command: `git config user.name "Yossi Dantes"`,
			want:    nil,
		},
		{
			name:    "git config --global user.email scrubbed under --global",
			command: "git config --global user.email yossi@malanta.ai",
			want:    []string{"malanta.ai"},
		},
		{
			name:    "git config --get user.name no value",
			command: "git config --get user.name",
			want:    nil,
		},
		{
			name:    "git config remote.origin.url + URL value retained",
			command: "git config remote.origin.url https://github.example/foo.git",
			want:    []string{"github.example"},
		},
		{
			name:    "git config --unset commit.gpgsign no hosts",
			command: "git config --unset commit.gpgsign",
			want:    nil,
		},
		{
			name:    "git config init.defaultBranch with non-PSL key still scrubbed safely",
			command: "git config --global init.defaultBranch main",
			want:    nil,
		},

		// --- git -c KEY=VAL per-command override -----------------------------
		// The -c flag is functionally equivalent to `git config` for the
		// duration of one invocation. KEY must always be scrubbed. The
		// VALUE-side behavior depends on whether the surrounding
		// subcommand is network-bearing:
		//   * Network subcommand (fetch / push / clone / pull / submodule
		//     update / remote add): value-side hosts MUST extract so a
		//     malicious-shape host (e.g. an http.proxy=<evil>) reaches
		//     the verdict cascade.
		//   * Non-network subcommand (commit / log / rebase / show / ...):
		//     the whole `git <subcmd>` segment is classified as
		//     non-network by isNonNetworkGitSubcommand, so the
		//     per-segment regex pass is suppressed entirely; the value
		//     side never reaches extraction. This is intentional —
		//     `git -c user.email=bot@whatever commit` doesn't contact
		//     `whatever`, it's just commit metadata.
		{
			name:    "git -c user.email=<email> fetch (network: value extracts)",
			command: "git -c user.email=bot@ci.example fetch origin",
			want:    []string{"ci.example"},
		},
		{
			name:    "git -c user.name=<name> commit (non-network: no hosts)",
			command: `git -c user.name="CI Bot" commit -m hello`,
			want:    nil,
		},
		{
			name:    "git -c http.proxy=<URL> fetch (network: proxy host extracts)",
			command: "git -c http.proxy=http://corp.proxy.example:8080 fetch",
			want:    []string{"corp.proxy.example"},
		},
		{
			name:    "git -c core.editor=<bin> rebase (non-network: no hosts)",
			command: "git -c core.editor=vim rebase -i HEAD~3",
			want:    nil,
		},
		{
			name:    "git -c user.email=<email> -c user.name=<name> push (chained -c, network)",
			command: `git -c user.email=bot@ci.example -c user.name="bot" push origin main`,
			want:    []string{"ci.example"},
		},
		{
			name:    "git -C path -c user.email=<email> fetch (-C global flag walked past)",
			command: "git -C /repo -c user.email=bot@ci.example fetch origin",
			want:    []string{"ci.example"},
		},
		{
			name:    "git --no-pager -c user.email=<email> log (non-network: suppressed)",
			command: "git --no-pager -c user.email=bot@ci.example log",
			want:    nil,
		},
		{
			name: "git -c user.email=<malicious-shape> commit still extracts value (defense-in-depth)",
			// `commit` is NOT in nonNetworkGitSubcommands on purpose:
			// commit messages routinely embed URLs (issue trackers,
			// docs, references). Suppressing the segment would lose
			// `git commit -m "see https://evil.example/..."` detection.
			// As a consequence, the value side of -c user.email=<host>
			// is also extracted, which is acceptable since legitimate
			// email domains label as legit at the API and the FP risk
			// only triggers on actually-suspicious-shape values.
			command: "git -c user.email=bot@malicious.example commit -m x",
			want:    []string{"malicious.example"},
		},
		{
			name:    "git -c http.proxy=<malicious> fetch MUST deny via proxy value",
			command: "git -c http.proxy=http://malicious.example:8080 fetch origin",
			want:    []string{"malicious.example"},
		},

		// --- git commit/tag/merge -m <message> ------------------------------
		// Commit messages are local repository metadata. Tokens inside
		// the message body (URLs, emails, dotted-config-key shapes)
		// are not network destinations on the commit operation itself,
		// and extracting them produces fail-closed denials on every
		// legitimate `git commit -m "fix user.email parsing"` style
		// invocation. See gitMessageRe's docstring for the threat-model
		// trade-off.
		{
			name:    "git commit -m with dotted-key in body",
			command: `git commit -m "fix the user.email parsing bug"`,
			want:    nil,
		},
		{
			name:    "git commit -m bareword value",
			command: "git commit -m noquotes",
			want:    nil,
		},
		{
			name:    "git commit --message= attached form",
			command: `git commit --message="release notes mention init.author.email"`,
			want:    nil,
		},
		{
			name:    "git commit --message <value> separate form",
			command: `git commit --message "covers core.account and default.region"`,
			want:    nil,
		},
		{
			name:    "git commit -m with single-quoted message",
			command: `git commit -m 'see notes about user.name and compute.region'`,
			want:    nil,
		},
		{
			name:    "git tag -m annotated tag message",
			command: `git tag -m "v1.0 release; updated user.email handling" v1.0`,
			want:    nil,
		},
		{
			name:    "git merge -m merge commit message",
			command: `git merge -m "merge: integrate init.author.email work" feature-branch`,
			want:    nil,
		},
		{
			name:    "git stash push -m description",
			command: `git stash push -m "WIP on user.email scrub"`,
			want:    nil,
		},
		{
			name:    "git stash save -m (older syntax)",
			command: `git stash save -m "older: user.email work"`,
			want:    nil,
		},
		{
			name:    "git notes add -m note body",
			command: `git notes add -m "FYI: relates to default.region rollout" HEAD`,
			want:    nil,
		},
		{
			name:    "git commit -a -m with multiple flags before -m",
			command: `git commit -a -s --no-verify -m "wip: refactor user.email handling"`,
			want:    nil,
		},
		{
			name: "git commit -m message with embedded URL",
			// The URL is in the commit message — accepted exfil trade-off
			// per gitMessageRe's docstring. Domain is NOT extracted.
			command: `git commit -m "see https://github.example/issues/42 for context"`,
			want:    nil,
		},

		// NEGATIVE cases for git*-message scrub: must NOT fire on
		// subcommands where -m has a non-message meaning, so legitimate
		// hosts in those commands' args still extract normally.
		{
			name:    "git revert -m <parent-number> NOT scrubbed (still extracts surrounding hosts)",
			command: "git revert -m 1 HEAD",
			want:    nil, // no hosts present; we just verify nothing weird happens
		},
		{
			name:    "git cherry-pick -m <parent-number> still extracts a real URL in args",
			command: "git cherry-pick -m 1 https://github.example/repo/commit/abc",
			want:    []string{"github.example"},
		},
		{
			name:    "git push -m would be invalid, but message scrub must not affect git push",
			command: "git push origin main",
			want:    nil,
		},
		{
			name:    "git fetch with -c override AND a message-looking flag elsewhere",
			command: "git -c user.email=bot@ci.example fetch origin",
			want:    []string{"ci.example"},
		},

		// --- npm / pnpm / yarn ----------------------------------------------
		{
			name:    "npm config set init.author.email + value",
			command: "npm config set init.author.email yossi@malanta.ai",
			want:    []string{"malanta.ai"},
		},
		{
			name:    "npm config get init.author.name",
			command: "npm config get init.author.name",
			want:    nil,
		},
		{
			name:    "pnpm config delete init.author.email",
			command: "pnpm config delete init.author.email",
			want:    nil,
		},
		{
			name:    "yarn config set init.author.url + URL value retained",
			command: "yarn config set init.author.url https://github.example/foo",
			want:    []string{"github.example"},
		},

		// --- kubectl config -------------------------------------------------
		{
			name:    "kubectl config set users.alice.client-key-data",
			command: "kubectl config set users.alice.client-key-data secret",
			want:    nil,
		},
		{
			name:    "kubectl config set clusters.prod.server + URL value retained",
			command: "kubectl config set clusters.prod.server https://k8s.example:6443",
			want:    []string{"k8s.example"},
		},
		{
			name:    "kubectl config unset users.alice.token",
			command: "kubectl config unset users.alice.token",
			want:    nil,
		},

		// --- aws configure --------------------------------------------------
		{
			name:    "aws configure set default.region",
			command: "aws configure set default.region us-east-1",
			want:    nil,
		},
		{
			name:    "aws configure set profile.foo.region",
			command: "aws configure set profile.foo.region us-west-2",
			want:    nil,
		},
		{
			name:    "aws configure get profile.foo.region",
			command: "aws configure get profile.foo.region",
			want:    nil,
		},

		// --- gcloud config --------------------------------------------------
		{
			name:    "gcloud config set core.account + value email-shaped",
			command: "gcloud config set core.account yossi@malanta.ai",
			want:    []string{"malanta.ai"},
		},
		{
			name:    "gcloud config set core.project",
			command: "gcloud config set core.project my-proj-123",
			want:    nil,
		},
		{
			name:    "gcloud config set compute.region",
			command: "gcloud config set compute.region us-central1",
			want:    nil,
		},
		{
			name:    "gcloud config unset compute.zone",
			command: "gcloud config unset compute.zone",
			want:    nil,
		},
		{
			name:    "gcloud config get-value core.project",
			command: "gcloud config get-value core.project",
			want:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
			// "no hosts expected" is the dominant case here; collapse the
			// nil-vs-empty-slice distinction so the test matches both
			// Dedup's empty-slice return and a literal nil.
			if len(tc.want) == 0 {
				if len(got) != 0 {
					t.Errorf("FromShell(%q) = %v, want no hosts", tc.command, got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("FromShell(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}

// --- Regression block -------------------------------------------------------
//
// These cases existed (or could have existed) before the scrub. They must
// continue to behave the same way after the scrub - the per-tool regex must
// not accidentally fire on a non-config invocation and suppress a real URL.

func TestFromShell_GitCloneURLStillExtracted(t *testing.T) {
	got := FromShell("git clone https://github.example/foo/bar.git")
	want := []string{"github.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_KubectlApplyURLStillExtracted(t *testing.T) {
	got := FromShell("kubectl apply -f https://manifest.example/x.yaml")
	want := []string{"manifest.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_CurlStillExtracted(t *testing.T) {
	got := FromShell("curl https://malanta.ai/api")
	want := []string{"malanta.ai"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_NpmInstallNoHosts(t *testing.T) {
	if got := FromShell("npm install"); len(got) != 0 {
		t.Errorf("got %v want no hosts", got)
	}
}

// TestFromShell_GitConfigScrubDoesNotEatLaterHost verifies that the
// non-greedy boundary on the git-config regex doesn't accidentally
// consume real URLs that appear AFTER the config invocation on a
// composite command line.
func TestFromShell_GitConfigScrubDoesNotEatLaterHost(t *testing.T) {
	got := FromShell("git config user.email yossi@malanta.ai && curl https://github.example/")
	// Expect both the value-side host and the trailing curl host. Dedup is
	// already applied by FromShell.
	want := []string{"malanta.ai", "github.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}
