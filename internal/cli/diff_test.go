package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// editedSeed writes a copy of the seed export with four edits: HTTPS
// required, a new wildcard redirect URI, implicit flow turned off, and a
// new client secret.
func editedSeed(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(seedExport)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["sslRequired"] = "external"
	for _, c := range doc["clients"].([]any) {
		client := c.(map[string]any)
		switch client["clientId"] {
		case "mobile-app":
			client["redirectUris"] = append(client["redirectUris"].([]any), "https://mobile.acme.example/*")
		case "web-spa":
			client["implicitFlowEnabled"] = false
		case "billing-service":
			client["secret"] = "rotated-secret"
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "edited.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiffText(t *testing.T) {
	code, stdout, stderr := run("diff", seedExport, editedSeed(t))
	if code != ExitFindings {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, ExitFindings, stderr)
	}
	want := `4 changes in 1 realm. 1 new finding, 2 resolved.

Realm acme
  ~ clients["billing-service"].secret (value hidden)
  + clients["mobile-app"].redirectUris: "https://mobile.acme.example/*"
  ~ clients["web-spa"].implicitFlowEnabled: true -> false
  ~ sslRequired: "none" -> "external"

New findings
  LOW       Redirect URIs use wildcards [redirect-uri-wildcard]
            acme, client "mobile-app": redirect URI "https://mobile.acme.example/*" allows any path

Resolved findings
  HIGH      HTTPS is not required [ssl-required-none]
            acme: sslRequired is "none"
  MEDIUM    Implicit flow is enabled [implicit-flow-enabled]
            acme, client "web-spa": implicit flow is enabled
`
	if stdout != want {
		t.Errorf("output differs\n--- got ---\n%s\n--- want ---\n%s", stdout, want)
	}
	if strings.Contains(stdout, "rotated-secret") || strings.Contains(stdout, "**********") {
		t.Error("output contains a secret value")
	}
}

func TestDiffJSON(t *testing.T) {
	code, stdout, stderr := run("diff", "--format", "json", seedExport, editedSeed(t))
	if code != ExitFindings {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, ExitFindings, stderr)
	}
	var doc struct {
		SchemaVersion int `json:"schemaVersion"`
		Summary       struct {
			Changes, NewFindings, ResolvedFindings int
		} `json:"summary"`
		Changes []struct {
			Realm, Path, Kind string
			Before, After     any
			Hidden            bool
		} `json:"changes"`
		NewFindings []struct {
			Check, Severity string
		} `json:"newFindings"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if doc.SchemaVersion != 1 || doc.Summary.Changes != 4 || doc.Summary.NewFindings != 1 || doc.Summary.ResolvedFindings != 2 {
		t.Errorf("schemaVersion=%d summary=%+v", doc.SchemaVersion, doc.Summary)
	}
	secret := doc.Changes[0]
	if secret.Path != `clients["billing-service"].secret` || !secret.Hidden || secret.Before != nil || secret.After != nil {
		t.Errorf("secret change = %+v, want hidden with no values", secret)
	}
	implicit := doc.Changes[2]
	if implicit.Before != true || implicit.After != false {
		t.Errorf("implicit flow change = %+v, want true -> false", implicit)
	}
	if doc.NewFindings[0].Check != "redirect-uri-wildcard" || doc.NewFindings[0].Severity != "low" {
		t.Errorf("new finding = %+v", doc.NewFindings[0])
	}
}

func TestDiffNoChanges(t *testing.T) {
	code, stdout, _ := run("diff", seedExport, "../../testdata/realms/26.8.0/dir")
	if code != ExitOK || stdout != "No changes.\n" {
		t.Errorf("exit code = %d, stdout = %q; want 0 and \"No changes.\"", code, stdout)
	}
}

func TestDiffErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"one export", []string{"diff", seedExport}, "need exactly two exports"},
		{"three exports", []string{"diff", seedExport, seedExport, seedExport}, "got 3"},
		{"bad format", []string{"diff", "--format", "yaml", seedExport, seedExport}, `unknown format "yaml"`},
		{"missing before", []string{"diff", "nope.json", seedExport}, "nope.json"},
		{"missing after", []string{"diff", seedExport, "nope.json"}, "nope.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(tt.args...)
			if code != ExitUsage || stdout != "" || !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("code=%d stdout=%q stderr=%q; want %d, empty stdout, stderr containing %q",
					code, stdout, stderr, ExitUsage, tt.wantErr)
			}
		})
	}
}

func TestDiffHelp(t *testing.T) {
	code, stdout, _ := run("diff", "-h")
	if code != ExitOK || !strings.Contains(stdout, "realmlint diff [flags] <before> <after>") {
		t.Errorf("exit code = %d, stdout = %q", code, stdout)
	}
}
