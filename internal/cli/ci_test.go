package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "realmlint.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckFailOn(t *testing.T) {
	tests := []struct {
		args     []string
		wantCode int
	}{
		{[]string{"--fail-on", "high"}, ExitFindings},    // seed has high findings
		{[]string{"--fail-on", "critical"}, ExitOK},      // but no critical ones
		{[]string{"--fail-on", "none"}, ExitOK},          // never fail
		{[]string{"--min-severity", "critical"}, ExitOK}, // default follows --min-severity
		{[]string{"--min-severity", "critical", "--fail-on", "low"}, ExitFindings},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			code, _, stderr := run(append(append([]string{"check"}, tt.args...), seedExport)...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d; stderr: %s", code, tt.wantCode, stderr)
			}
		})
	}
}

func TestCheckSARIF(t *testing.T) {
	code, stdout, stderr := run("check", "--format", "sarif", seedExport)
	if code != ExitFindings {
		t.Fatalf("exit code = %d; stderr: %s", code, stderr)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &log); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs[0].Results) != 23 {
		t.Errorf("version=%s results=%d, want 2.1.0 and 23", log.Version, len(log.Runs[0].Results))
	}
}

func TestCheckConfigSuppresses(t *testing.T) {
	cfg := writeConfig(t, `
ignore:
  - check: full-scope-allowed
    reason: Accepted for now.
  - check: ssl-required-none
    realm: acme
    reason: TLS ends at the load balancer.
  - check: implicit-flow-enabled
    realm: someone-else
    reason: Stale entry.
`)
	code, stdout, stderr := run("check", "--config", cfg, seedExport)
	if code != ExitFindings {
		t.Fatalf("exit code = %d; stderr: %s", code, stderr)
	}
	if !strings.HasPrefix(stdout, "18 findings in 1 realm: 4 high, 11 medium, 3 low. 5 suppressed by configuration.") {
		t.Errorf("summary = %q", strings.SplitN(stdout, "\n", 2)[0])
	}
	if strings.Contains(stdout, "full-scope-allowed") || strings.Contains(stdout, "ssl-required-none") {
		t.Error("suppressed checks still appear in the output")
	}
	if !strings.Contains(stderr, "warning") || !strings.Contains(stderr, "implicit-flow-enabled in realm someone-else matched no findings") {
		t.Errorf("stderr = %q, want a warning about the stale entry", stderr)
	}
}

func TestCheckConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"missing config file", []string{"check", "--config", "nope.yaml", seedExport}, "nope.yaml"},
		{"invalid config", []string{"check", "--config", writeConfig(t, "ignore:\n  - check: ssl-required-none\n"), seedExport}, "reason is required"},
		{"bad fail-on", []string{"check", "--fail-on", "sometimes", seedExport}, "--fail-on"},
		{"bad format", []string{"check", "--format", "html", seedExport}, "text, json or sarif"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := run(tt.args...)
			if code != ExitUsage || !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("code=%d stderr=%q, want %d and %q", code, stderr, ExitUsage, tt.wantErr)
			}
		})
	}
}

func TestDiffConfigSuppressesNewFindings(t *testing.T) {
	cfg := writeConfig(t, "ignore:\n  - check: redirect-uri-wildcard\n    reason: Mobile deep links.\n")
	code, stdout, stderr := run("diff", "--config", cfg, seedExport, editedSeed(t))
	if code != ExitFindings {
		t.Fatalf("exit code = %d; stderr: %s", code, stderr)
	}
	if !strings.HasPrefix(stdout, "4 changes in 1 realm. 0 new findings, 2 resolved.") || strings.Contains(stdout, "New findings") {
		t.Errorf("output = %s", stdout)
	}
}
