package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

const seedExport = "../../testdata/realms/26.8.0/single.json"

func TestMain(m *testing.M) {
	// Fixed time so expiry and key-age findings do not change as the
	// fixtures get older.
	now = func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) }
	os.Exit(m.Run())
}

func run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestCheckTextMatchesGolden(t *testing.T) {
	code, stdout, stderr := run("check", seedExport)
	if code != ExitFindings {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, ExitFindings, stderr)
	}
	golden := filepath.Join("testdata", "check-seed.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(stdout), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run 'go test ./internal/cli -update' to create it)", err)
	}
	if stdout != string(want) {
		t.Errorf("output differs from %s (run with -update if the change is intended)\n--- got ---\n%s", golden, stdout)
	}
}

func TestCheckJSON(t *testing.T) {
	code, stdout, stderr := run("check", "--format", "json", seedExport)
	if code != ExitFindings {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, ExitFindings, stderr)
	}
	var doc struct {
		SchemaVersion int `json:"schemaVersion"`
		Tool          struct {
			Name string `json:"name"`
		} `json:"tool"`
		Summary struct {
			Realms     int            `json:"realms"`
			Findings   int            `json:"findings"`
			Shown      int            `json:"shown"`
			BySeverity map[string]int `json:"bySeverity"`
		} `json:"summary"`
		Findings []struct {
			Check    string `json:"check"`
			Severity string `json:"severity"`
			Realm    string `json:"realm"`
			Why      string `json:"why"`
			Fix      string `json:"fix"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if doc.SchemaVersion != 1 || doc.Tool.Name != "realmlint" {
		t.Errorf("schemaVersion=%d tool=%q", doc.SchemaVersion, doc.Tool.Name)
	}
	if doc.Summary.Realms != 1 || doc.Summary.Findings != 23 || doc.Summary.Shown != 23 || len(doc.Findings) != 23 {
		t.Errorf("summary = %+v with %d findings, want 1 realm and 23 findings", doc.Summary, len(doc.Findings))
	}
	if doc.Summary.BySeverity["high"] != 5 || doc.Summary.BySeverity["critical"] != 0 {
		t.Errorf("bySeverity = %v, want 5 high and 0 critical", doc.Summary.BySeverity)
	}
	f := doc.Findings[0]
	if f.Severity != "high" || f.Realm != "acme" || f.Why == "" || f.Fix == "" {
		t.Errorf("first finding = %+v, want a high finding on acme with why and fix", f)
	}
}

func TestCheckOptions(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		contains []string
		excludes []string
	}{
		{
			name:     "top limits output",
			args:     []string{"check", "--top", "3", seedExport},
			wantCode: ExitFindings,
			contains: []string{"23 findings in 1 realm: 5 high, 11 medium, 7 low. Showing the top 3."},
			excludes: []string{"MEDIUM", "LOW"},
		},
		{
			name:     "flags after paths",
			args:     []string{"check", seedExport, "--min-severity", "high"},
			wantCode: ExitFindings,
			contains: []string{"5 findings in 1 realm: 5 high. 18 findings below high not shown."},
			excludes: []string{"MEDIUM"},
		},
		{
			name:     "nothing at threshold exits 0",
			args:     []string{"check", "--min-severity=critical", seedExport},
			wantCode: ExitOK,
			contains: []string{"No findings in 1 realm. 23 findings below critical not shown."},
		},
		{
			name:     "path after double dash",
			args:     []string{"check", "--top", "1", "--", seedExport},
			wantCode: ExitFindings,
			contains: []string{"Showing the top 1."},
		},
		{
			name:     "directory export",
			args:     []string{"check", "../../testdata/realms/26.8.0/dir"},
			wantCode: ExitFindings,
			contains: []string{"23 findings in 1 realm"},
		},
		{
			name:     "help",
			args:     []string{"check", "--help"},
			wantCode: ExitOK,
			contains: []string{"realmlint check [flags] <file-or-directory>..."},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d; stderr: %s", code, tt.wantCode, stderr)
			}
			for _, s := range tt.contains {
				if !strings.Contains(stdout, s) {
					t.Errorf("stdout does not contain %q:\n%s", s, stdout)
				}
			}
			for _, s := range tt.excludes {
				if strings.Contains(stdout, s) {
					t.Errorf("stdout contains %q:\n%s", s, stdout)
				}
			}
		})
	}
}

func TestCheckErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no paths", []string{"check"}, "no realm export files"},
		{"unknown flag", []string{"check", "--colour", seedExport}, "flag provided but not defined"},
		{"bad format", []string{"check", "--format", "xml", seedExport}, `unknown format "xml"`},
		{"bad severity", []string{"check", "--min-severity", "urgent", seedExport}, `unknown severity "urgent"`},
		{"negative top", []string{"check", "--top", "-1", seedExport}, "--top must be 0 or more"},
		{"missing file", []string{"check", "nope.json"}, "nope.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(tt.args...)
			if code != ExitUsage {
				t.Errorf("exit code = %d, want %d", code, ExitUsage)
			}
			if stdout != "" {
				t.Errorf("stdout should be empty on error, got %q", stdout)
			}
			if !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantErr)
			}
		})
	}
}
