package extract

import (
	"reflect"
	"testing"
)

// These tests cover the per-tool extractors that the baseline TestFromShell_*
// suite did not exercise. They guard against regressions in flag-walking
// logic for the long tail of CLIs an agent might invoke.

func TestFromShell_HelmRepoAdd(t *testing.T) {
	got := FromShell("helm repo add stable https://charts.example/")
	want := []string{"charts.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_KubectlServerFlag(t *testing.T) {
	got := FromShell("kubectl --server https://k8s.example:6443 get pods")
	want := []string{"k8s.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_KubectlServerEqualFlag(t *testing.T) {
	got := FromShell("kubectl --server=https://k8s.example:6443 get pods")
	want := []string{"k8s.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_PodmanRegistry(t *testing.T) {
	got := FromShell("podman pull ghcr.example/org/img:tag")
	want := []string{"ghcr.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_UvWithIndex(t *testing.T) {
	got := FromShell("uv pip install --index-url https://pypi.example/simple foo")
	want := []string{"pypi.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_PoetryWithExtraIndex(t *testing.T) {
	got := FromShell("poetry add --extra-index-url=https://mirror.example/ pkg")
	want := []string{"mirror.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_RsyncRemote(t *testing.T) {
	got := FromShell("rsync -a user@backup.example:/data/ ./local/")
	want := []string{"backup.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_ScpRemote(t *testing.T) {
	got := FromShell("scp file.tgz deploy@drop.example:/srv/")
	want := []string{"drop.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_FindLinks(t *testing.T) {
	got := FromShell("pip install --find-links https://wheels.example/index.html foo")
	want := []string{"wheels.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

// TestFromShell_DockerWithDigest exercises the @sha256:... stripping path in
// fromDockerArgs.
func TestFromShell_DockerWithDigest(t *testing.T) {
	got := FromShell("docker pull ghcr.example/foo@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	want := []string{"ghcr.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

// --- Windows executable-suffix regression -----------------------------------
//
// These tests cover the pre-existing latent bug fixed in Phase A of the
// context-aware shell extraction plan: the per-tool dispatch in step 4
// of FromShellInDir was keyed on the lowercased basename of tokens[0],
// which on Windows would be `curl.exe` / `docker.exe` / `pip.exe` and
// fall through to the generic regex pass without ever hitting the
// targeted extractor. The stripExeExt pass at the dispatch site lets
// one switch case serve both `curl` (POSIX) and `curl.exe` (Windows).
//
// We assert ONLY behavior visible at the FromShell boundary; the
// stripExeExt unit-level lockdown lives in shell_netdiag_test.go.

func TestFromShell_CurlExeOnWindows(t *testing.T) {
	got := FromShell("curl.exe https://Example.COM/path")
	want := []string{"example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_DockerExeOnWindows(t *testing.T) {
	// Before stripExeExt, docker.exe would NOT hit `case "docker"` and the
	// registry-host extraction in fromDockerArgs would not run. The generic
	// regex still produces "ghcr.example" here because the image reference
	// happens to match urlOrHostRe directly, so the visible behavior is
	// the same — but the regression we're locking down is that the per-tool
	// path is exercised. We don't assert the path was taken (no observable
	// difference); we assert the output is correct, which is what an
	// integration-level test guarantees.
	got := FromShell("docker.exe pull ghcr.example/foo/bar:tag")
	want := []string{"ghcr.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFromShell_PipExeOnWindows(t *testing.T) {
	got := FromShell("pip.exe install --index-url https://pypi.example/simple foo")
	want := []string{"pypi.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}
