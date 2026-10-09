package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/realmlint/realmlint/pkg/check"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "realmlint.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAndApply(t *testing.T) {
	cfg, err := Load(write(t, `
ignore:
  - check: full-scope-allowed
    reason: Every client needs the user's roles.
  - check: redirect-uri-http
    realm: acme
    object: 'client "legacy-portal"'
    reason: Internal only, retired next quarter.
  - check: implicit-flow-enabled
    realm: other
    reason: Never matches.
`))
	if err != nil {
		t.Fatal(err)
	}
	findings := []check.Finding{
		{CheckID: "full-scope-allowed", Realm: "acme", Object: `client "a"`},
		{CheckID: "full-scope-allowed", Realm: "beta", Object: `client "b"`},
		{CheckID: "redirect-uri-http", Realm: "acme", Object: `client "legacy-portal"`},
		{CheckID: "redirect-uri-http", Realm: "acme", Object: `client "shop"`},
		{CheckID: "implicit-flow-enabled", Realm: "acme", Object: `client "spa"`},
	}
	kept, suppressed, unused := cfg.Apply(findings)
	if suppressed != 3 || len(kept) != 2 {
		t.Fatalf("suppressed=%d kept=%d, want 3 and 2", suppressed, len(kept))
	}
	if kept[0].Object != `client "shop"` || kept[1].CheckID != "implicit-flow-enabled" {
		t.Errorf("kept = %+v", kept)
	}
	if len(unused) != 1 || unused[0].Realm != "other" {
		t.Errorf("unused = %+v, want the entry for realm other", unused)
	}
}

func TestLoadDefaultFile(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg, err := Load("")
	if err != nil || cfg.Path != "" || len(cfg.Ignore) != 0 {
		t.Fatalf("missing default file: cfg=%+v err=%v, want empty config", cfg, err)
	}
	if err := os.WriteFile(DefaultFile, []byte("ignore:\n  - check: brute-force-disabled\n    reason: Handled by the WAF.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load("")
	if err != nil || cfg.Path != DefaultFile || len(cfg.Ignore) != 1 {
		t.Fatalf("default file: cfg=%+v err=%v", cfg, err)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name, content, wantErr string
	}{
		{"missing check", "ignore:\n  - reason: x\n", "check is required"},
		{"unknown check", "ignore:\n  - check: no-such-check\n    reason: x\n", `unknown check "no-such-check"`},
		{"missing reason", "ignore:\n  - check: brute-force-disabled\n", "reason is required"},
		{"unknown field", "ignore:\n  - check: brute-force-disabled\n    reason: x\n    client: web\n", "field client not found"},
		{"bad yaml", "ignore: [", "yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(write(t, tt.content))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("an explicitly named missing file should be an error")
	}
}

func TestEmptyFileIsValid(t *testing.T) {
	cfg, err := Load(write(t, "# nothing ignored yet\n"))
	if err != nil || len(cfg.Ignore) != 0 {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
}
