package main

import (
	"runtime"
	"testing"
)

// setTestHome points home-directory resolution at dir for the duration of a
// test.
//
// Both variables are set because os.UserHomeDir() — which every CLI path
// that writes state goes through — reads USERPROFILE on Windows and HOME
// everywhere else. Setting only HOME left Windows runs writing their grant
// and key files into the runner's real profile while the assertions read an
// empty temp dir, which is what made these tests fail on Windows only.
func setTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	}
}
