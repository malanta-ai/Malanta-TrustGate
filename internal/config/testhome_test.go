package config

import (
	"runtime"
	"testing"
)

// setTestHome points home-directory resolution at dir for the duration of a
// test.
//
// Both variables are set because EnvFiles() and the config.json lookup
// resolve the home directory via os.UserHomeDir(), which reads USERPROFILE
// on Windows and HOME everywhere else. Setting only HOME left Windows runs
// reading the runner's real profile instead of the test's fixture.
func setTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	}
}
