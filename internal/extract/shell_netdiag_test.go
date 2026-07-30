package extract

import (
	"reflect"
	"testing"
)

// These tests cover the network-diagnostic tool dispatch in the
// context-aware shell extractor.
//
// Without this dispatch, tools like `ping evil.example` and
// `dig evil.example` produced no extracted hosts because their target
// argument is a bare hostname with no scheme / port / path — the
// generic urlOrHostRe would match it, but Layer 2 (Phase C) would
// drop it as a "bare token without URL context" once that layer is in
// place. Dispatching on the leading binary makes the extraction
// robust against the URL-context filter and also gives a clearer
// signal in the decision log about which tool tried to reach the
// target.
//
// The same case set is exercised for POSIX (ping, dig, ...) and
// Windows / PowerShell (tracert, Test-NetConnection, Resolve-DnsName,
// ...). On Windows the executable suffix may be present
// (`ping.exe evil.example`); stripExeExt feeds the lookup with the
// suffix-less form so one switch case serves both shapes.

func TestFromShell_NetDiag_POSIX(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "ping bare host",
			command: "ping evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "ping with -c flag walked past",
			command: "ping -c 4 evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "ping multi-host",
			command: "ping evil.example example.org",
			want:    []string{"evil.example", "example.org"},
		},
		{
			name:    "dig bare host",
			command: "dig evil.example",
			want:    []string{"evil.example"},
		},
		{
			// The `@192.0.2.8` token is skipped by fromNetworkDiagArgs, but
			// the generic urlOrHostRe pass still extracts the bare IPv4
			// because Malanta can answer IPv4 lookups again. This is
			// intentional — see the NOTE in fromNetworkDiagArgs's doc.
			name:    "dig with public resolver still extracts both",
			command: "dig @192.0.2.8 evil.example",
			want:    []string{"192.0.2.8", "evil.example"},
		},
		{
			name:    "dig with +short flag-like option",
			command: "dig +short evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "nslookup bare host",
			command: "nslookup evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "host bare host",
			command: "host evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "nc with all-digit port stripped",
			command: "nc evil.example 80",
			want:    []string{"evil.example"},
		},
		{
			name:    "nc -l listen mode no host",
			command: "nc -l 8080",
			want:    nil,
		},
		{
			name:    "telnet host + port",
			command: "telnet evil.example 25",
			want:    []string{"evil.example"},
		},
		{
			name:    "whois bare domain",
			command: "whois evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "traceroute bare host",
			command: "traceroute evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "mtr bare host",
			command: "mtr evil.example",
			want:    []string{"evil.example"},
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

func TestFromShell_NetDiag_Windows(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "tracert bare host",
			command: "tracert evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "ping.exe with suffix",
			command: "ping.exe evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "tracert.exe with suffix",
			command: "tracert.exe evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "Test-NetConnection bare cmdlet",
			command: "Test-NetConnection evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "tnc PowerShell alias",
			command: "tnc evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "tnc with -Port flag walked past",
			command: "tnc evil.example -Port 443",
			want:    []string{"evil.example"},
		},
		{
			name:    "Resolve-DnsName bare cmdlet",
			command: "Resolve-DnsName evil.example",
			want:    []string{"evil.example"},
		},
		{
			name:    "Test-Connection bare cmdlet",
			command: "Test-Connection evil.example",
			want:    []string{"evil.example"},
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

// TestStripExeExt locks down the suffix-stripping contract directly,
// independent of FromShell. The set of recognized suffixes is
// intentionally narrow (matches exeExts); add a case here when you
// add a suffix.
func TestStripExeExt(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"curl", "curl"},
		{"curl.exe", "curl"},
		{"docker.com", "docker"}, // legacy 16-bit Windows-style; idempotent on POSIX
		{"setup.bat", "setup"},
		{"task.cmd", "task"},
		{"get-content.ps1", "get-content"},
		{"module.psm1", "module"},
		{"binary-without-suffix", "binary-without-suffix"},
		{"", ""},
		// .tar.gz wouldn't match .gz (not in exeExts) — verify we don't
		// accidentally strip non-executable suffixes:
		{"archive.tar.gz", "archive.tar.gz"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := stripExeExt(tc.in); got != tc.want {
				t.Errorf("stripExeExt(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
