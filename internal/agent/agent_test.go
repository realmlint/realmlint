package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func run(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	for _, k := range []string{"REALMLINT_KEYCLOAK_URL", "REALMLINT_CLIENT_ID", "REALMLINT_CLIENT_SECRET"} {
		t.Setenv(k, env[k])
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestUsageErrors(t *testing.T) {
	withSecret := map[string]string{"REALMLINT_CLIENT_SECRET": "s"}
	tests := []struct {
		name    string
		env     map[string]string
		args    []string
		wantErr string
	}{
		{"no url", withSecret, []string{"--out", "x"}, "--keycloak-url"},
		{"bad scheme", withSecret, []string{"--keycloak-url", "sso.example.com", "--out", "x"}, "https:// or http://"},
		{"no out", withSecret, []string{"--keycloak-url", "https://sso.example.com"}, "--out is required"},
		{"no secret", nil, []string{"--keycloak-url", "https://sso.example.com", "--out", "x"}, "REALMLINT_CLIENT_SECRET"},
		{"interval too short", withSecret, []string{"--keycloak-url", "https://sso.example.com", "--out", "x", "--interval", "10s"}, "at least 1m"},
		{"stray argument", withSecret, []string{"--keycloak-url", "https://sso.example.com", "--out", "x", "extra"}, `unexpected argument "extra"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := run(t, tt.env, tt.args...)
			if code != ExitUsage || !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("code=%d stderr=%q, want %d and %q", code, stderr, ExitUsage, tt.wantErr)
			}
		})
	}
}

func TestParseDefaultsAndRealms(t *testing.T) {
	t.Setenv("REALMLINT_KEYCLOAK_URL", "https://sso.example.com")
	t.Setenv("REALMLINT_CLIENT_SECRET", "s")
	t.Setenv("REALMLINT_CLIENT_ID", "")
	var out, errOut bytes.Buffer
	cfg, code := parse([]string{"--out", "x", "--realm", "a,b", "--realm", " c "}, &out, &errOut)
	if code != -1 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if cfg.ClientID != "realmlint-agent" || cfg.AuthRealm != "master" || cfg.EventsSince != 24*time.Hour || cfg.Interval != 0 {
		t.Errorf("defaults = %+v", cfg)
	}
	if strings.Join(cfg.Realms, ",") != "a,b,c" {
		t.Errorf("realms = %v", cfg.Realms)
	}
}

func TestHelpAndVersion(t *testing.T) {
	if code, out, _ := run(t, nil, "--help"); code != ExitOK || !strings.Contains(out, "view-identity-providers") {
		t.Errorf("help: code=%d", code)
	}
	if code, out, _ := run(t, nil, "--version"); code != ExitOK || !strings.HasPrefix(out, "realmlint-agent ") {
		t.Errorf("version: code=%d out=%q", code, out)
	}
}

func TestUnreachableKeycloakFailsTheRun(t *testing.T) {
	out := t.TempDir()
	code, _, stderr := run(t, map[string]string{"REALMLINT_CLIENT_SECRET": "s"},
		"--keycloak-url", "http://127.0.0.1:1", "--out", out)
	if code != ExitError || !strings.Contains(stderr, "log in to Keycloak") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != 0 {
		t.Errorf("nothing should be written on failure, found %d entries", len(entries))
	}
}

func TestWriteJSONIsAtomicAndNamesAreSafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events", safeName("a/b")+".json")
	if err := writeJSON(path, map[string]any{"realm": "a/b"}); err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "a_b.json" {
		t.Errorf("file name = %s", filepath.Base(path))
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %d entries", len(entries))
	}
}
