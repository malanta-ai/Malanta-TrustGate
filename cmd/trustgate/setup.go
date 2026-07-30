package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/malanta-ai/Malanta-TrustGate/internal/config"
	"golang.org/x/term"
)

// keyFilePath returns the per-user env file path (~/.config/trustgate/env).
// This is deliberately the SAME path internal/config.EnvFiles() reads
// (precedence entry 2 of 3) so a key written here is picked up by every
// hook binary with zero further configuration. A small local literal
// rather than something threaded through internal/config: this file DOES
// import internal/config (see resolveKeyEnvVar) to detect the configured
// provider, but the destination PATH itself needs no config to compute.
func keyFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".config", "trustgate", "env"), nil
}

// resolveKeyEnvVar determines which environment variable `trustgate setup`
// should prompt for and store, and a short display name for the prompt
// text. override (the --env-var flag) always wins when non-empty — the
// escape hatch for a vendor config that hasn't landed in config.json yet,
// or a non-standard install. Otherwise it loads the SAME effective config
// a hook process would see (config.LoadWithEnvFiles — layered defaults <
// config.json < env files < process env) and, for provider "generic" with
// an auth env var configured, uses that instead of the Malanta default —
// so switching provider in config.json is enough to make setup store the
// right key with no extra flag. A config-load error here is deliberately
// non-fatal: setup's whole job can be fixing a broken install, so it falls
// back to the Malanta default rather than refusing to run.
func resolveKeyEnvVar(override string) (envVar, displayName string) {
	if override != "" {
		return override, override
	}
	cfg, err := config.LoadWithEnvFiles()
	if err == nil && strings.EqualFold(strings.TrimSpace(cfg.Provider), "generic") &&
		cfg.Generic != nil && cfg.Generic.Auth.EnvVar != "" {
		name := cfg.Generic.Name
		if name == "" {
			name = "generic"
		}
		return cfg.Generic.Auth.EnvVar, name
	}
	return "MALANTA_API_KEY", "Malanta"
}

func runSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	keyFlag := fs.String("key", "", "API key value (omit to be prompted, or set the target env var directly)")
	envVarFlag := fs.String("env-var", "", "override which env var to store the key under (default: auto-detected from the configured provider — MALANTA_API_KEY, or a generic provider's auth.env_var)")
	reset := fs.Bool("reset", false, "overwrite an existing key file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	envVar, displayName := resolveKeyEnvVar(*envVarFlag)

	// --key places the secret in argv, where it is visible in
	// shell history and process listings (ps / /proc). Keep it working for
	// non-interactive automation that already accepts the trade-off, but
	// warn loudly and steer toward the env var / interactive prompt. The
	// flag is deprecated and may be removed.
	if *keyFlag != "" {
		fmt.Fprintf(os.Stderr,
			"warning: --key exposes the secret on the command line (shell history, ps/argv). "+
				"Prefer setting %s in the environment and running `trustgate setup` without --key, "+
				"or the interactive prompt. --key is deprecated.\n", envVar)
	}

	path, err := keyFilePath()
	if err != nil {
		return err
	}

	if _, err := os.Stat(path); err == nil && !*reset {
		return fmt.Errorf("%s already exists; pass --reset to overwrite", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	key := *keyFlag
	if key == "" {
		key = os.Getenv(envVar)
	}
	if key == "" {
		key, err = promptForKey(displayName)
		if err != nil {
			return err
		}
	}
	if key == "" {
		return fmt.Errorf("no key provided (use --key, set %s, or run interactively)", envVar)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	// MkdirAll leaves a PRE-EXISTING directory's mode untouched, so
	// on a machine where ~/.config/trustgate was created world-readable by
	// something else, tighten it explicitly to 0700 (non-Windows; Windows
	// perms are handled by the icacls lockdown below).
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("restrict config directory perms: %w", err)
		}
	}
	// On --reset over an existing key file, os.WriteFile's mode arg
	// applies only when CREATING the file — an existing, looser-mode file
	// keeps its old bits. Remove any existing file first so WriteFile always
	// creates fresh at 0600 (and there's no window where the new secret sits
	// under the old, permissive mode).
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove existing %s before rewrite: %w", path, err)
	}
	// 0600, matching install-hooks.sh's umask 077 posture — this file
	// carries the reputation-provider API key. On Windows, os.FileMode
	// permission bits don't map to real ACLs (Go's chmod there only
	// toggles the read-only attribute), so lockdownWindowsACL below does
	// the actual current-user-only restriction via icacls, mirroring
	// what install-hooks.ps1 has always done.
	if err := os.WriteFile(path, []byte(envVar+"="+key+"\n"), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		// Belt-and-suspenders: force 0600 even if an unusual umask or a
		// pre-existing inode affected the create mode.
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("restrict %s perms: %w", path, err)
		}
	}
	if err := lockdownWindowsACL(path); err != nil {
		// An unprotected secret must NEVER be left on disk. On
		// Windows the 0600 mode above is a no-op, so icacls is the ONLY
		// thing restricting the file to the current user — if it fails, the
		// key is world-readable. Remove it and fail closed rather than
		// leaving the secret exposed with a mere warning.
		_ = os.Remove(path)
		return fmt.Errorf("could not restrict %s to the current user via icacls; key NOT stored: %w", path, err)
	}

	fmt.Printf("Stored %s at %s (mode 0600%s).\n", envVar, path, aclSuffix())
	fmt.Println("Restart Cursor (or reload the window) so the hooks pick it up.")
	return nil
}

// lockdownWindowsACL restricts path to the current user only, the
// Windows equivalent of the 0600 permission bits above. No-op on
// non-Windows (the os.WriteFile mode already did the job via umask).
// Shells out to icacls rather than golang.org/x/sys/windows ACL APIs to
// keep this CLI's Windows behavior identical, command-for-command, to
// what install-hooks.ps1 has always run.
func lockdownWindowsACL(path string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	user := os.Getenv("USERNAME")
	if user == "" {
		return errors.New("USERNAME environment variable is not set")
	}
	cmd := exec.Command("icacls", path, "/inheritance:r", "/grant:r", user+":F")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %w: %s", err, out)
	}
	return nil
}

func aclSuffix() string {
	if runtime.GOOS == "windows" {
		return ", ACL: current user only"
	}
	return ""
}

// promptForKey reads the key with echo disabled when stdin is a terminal,
// falling back to a plain (echoed) read otherwise — e.g. when piped in a
// script or CI, where there's no terminal to disable echo on and the
// caller is presumably already handling secrecy upstream (redirected from
// a secrets manager, not a human's screen). displayName names the
// provider/vendor in the prompt text (see resolveKeyEnvVar) — "Malanta"
// for the default provider, so the prompt reads exactly as it always has.
func promptForKey(displayName string) (string, error) {
	fmt.Fprintf(os.Stderr, "Enter your %s API key: ", displayName)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read key: %w", err)
		}
		return string(b), nil
	}
	var key string
	if _, err := fmt.Fscanln(os.Stdin, &key); err != nil {
		return "", fmt.Errorf("read key: %w", err)
	}
	return key, nil
}
