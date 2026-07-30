//go:build !windows

package extract

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestFromScriptFile_FIFOIsRejectedAndDoesNotBlock is the regular-file
// guard: a FIFO planted at a script path must be rejected without
// blocking. The pre-fix code stat'd the FIFO (Size 0, under the cap) and then
// os.ReadFile'd it, which blocks until a writer appears — hanging the hook
// until Cursor's timeout and turning a benign command into a fail-closed
// denial.
func TestFromScriptFile_FIFOIsRejectedAndDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "payload.sh")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported on this platform: %v", err)
	}

	done := make(chan []string, 1)
	go func() { done <- fromScriptFile(fifo, dir) }()

	select {
	case got := <-done:
		if len(got) != 0 {
			t.Errorf("expected no hosts from a FIFO, got %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fromScriptFile blocked on a FIFO: it must reject non-regular files without reading")
	}
}

// TestFromScriptFile_RegularFileStillWorks confirms that guard did
// not break the normal path: a regular script body is still read and its
// hosts extracted.
func TestFromScriptFile_RegularFileStillWorks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(p, []byte("curl https://followed-host.example/x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := fromScriptFile(p, dir)
	found := false
	for _, h := range got {
		if h == "followed-host.example" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected followed-host.example from a regular script body, got %v", got)
	}
}
