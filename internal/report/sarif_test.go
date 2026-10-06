package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/realmlint/realmlint/internal/check"
	"github.com/realmlint/realmlint/internal/realm"
)

func TestSARIF(t *testing.T) {
	const export = "../../testdata/realms/26.8.0/single.json"
	realms, err := realm.Load(export)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	res := Build(realms, check.Run(realms, check.All(), now), check.Low, 0)

	var buf bytes.Buffer
	if err := SARIF(&buf, res, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID      string `json:"id"`
						HelpURI string `json:"helpUri"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("version=%q runs=%d", log.Version, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "realmlint" || run.Tool.Driver.Version != "1.2.3" || len(run.Tool.Driver.Rules) != len(check.All()) {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Results) != 23 {
		t.Fatalf("got %d results, want 23", len(run.Results))
	}

	lines := fileLines(t, export)
	fingerprints := map[string]bool{}
	for _, r := range run.Results {
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("result %s has ruleIndex %d pointing at %s", r.RuleID, r.RuleIndex, run.Tool.Driver.Rules[r.RuleIndex].ID)
		}
		loc := r.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI != export || loc.Region.StartLine < 1 {
			t.Errorf("result %s location = %+v", r.RuleID, loc)
		}
		fp := r.PartialFingerprints["realmlintFinding/v1"]
		if fp == "" || fingerprints[fp] {
			t.Errorf("result %s has a missing or duplicate fingerprint", r.RuleID)
		}
		fingerprints[fp] = true

		// Spot-check that findings point at the right line.
		line := lines[loc.Region.StartLine-1]
		switch {
		case r.RuleID == "ssl-required-none" && !strings.Contains(line, `"sslRequired"`):
			t.Errorf("ssl-required-none points at line %d: %s", loc.Region.StartLine, line)
		case r.RuleID == "implicit-flow-enabled" && !strings.Contains(line, `"clientId": "web-spa"`):
			t.Errorf("implicit-flow-enabled points at line %d: %s", loc.Region.StartLine, line)
		case r.RuleID == "admin-without-mfa" && !strings.Contains(line, `"username": "alice"`):
			t.Errorf("admin-without-mfa points at line %d: %s", loc.Region.StartLine, line)
		case r.RuleID == "service-account-admin" && !strings.Contains(line, `"serviceAccountClientId": "billing-service"`):
			t.Errorf("service-account-admin points at line %d: %s", loc.Region.StartLine, line)
		case r.RuleID == "idp-signature-not-validated" && !strings.Contains(line, `"alias": "partner-saml"`):
			t.Errorf("idp-signature-not-validated points at line %d: %s", loc.Region.StartLine, line)
		}
	}

	levels := map[string]int{}
	for _, r := range run.Results {
		levels[r.Level]++
	}
	if levels["error"] != 5 || levels["warning"] != 11 || levels["note"] != 7 {
		t.Errorf("levels = %v, want 5 error, 11 warning, 7 note", levels)
	}
}

func TestSARIFURI(t *testing.T) {
	if got := sarifURI("./exports/acme.json"); got != "exports/acme.json" {
		t.Errorf("relative path = %q", got)
	}
	abs := filepath.Join(t.TempDir(), "acme.json")
	if got := sarifURI(abs); !strings.HasPrefix(got, "file:///") {
		t.Errorf("absolute path = %q, want a file:/// URI", got)
	}
}

func fileLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(string(data), "\n")
}
