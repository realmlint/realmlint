package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const olderExport = "../../testdata/realms/26.6.4/single.json"

func TestUpgradeFromExportVersion(t *testing.T) {
	code, stdout, stderr := run("upgrade", olderExport)
	if code != ExitFindings {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, ExitFindings, stderr)
	}
	for _, want := range []string{
		"Upgrading Keycloak 26.6.4 to 26.8.0",
		"'Full scope allowed' switch on clients is deprecated  [deprecated, 26.8.0]",
		"acme  Client web-spa: Full scope allowed is on",
		"https://www.keycloak.org/docs/latest/upgrading/index.html#full-scope-allowed-switch-on-clients-is-deprecated",
		"Breaking or removed, read before upgrading",
		"Add --all to list them.",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	// 26.6.0 is not part of an upgrade from 26.6.4.
	if strings.Contains(stdout, "New brute force locking mechanism") {
		t.Error("listed a change from before the running version")
	}
}

func TestUpgradeJSONAndFlags(t *testing.T) {
	code, stdout, stderr := run("upgrade", "--from", "26.6.4", "--to", "26.7.0", "--format", "json", olderExport)
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d (nothing checked up to 26.7.0 affects the seed); stderr: %s", code, ExitOK, stderr)
	}
	var rep struct {
		Guide, From, To string
		Items           []struct{ Version, Status, URL string }
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.From != "26.6.4" || rep.To != "26.7.0" || len(rep.Items) == 0 || !strings.HasPrefix(rep.Items[0].URL, rep.Guide+"#") {
		t.Fatalf("report: %+v", rep)
	}
	for _, it := range rep.Items {
		if it.Version == "26.8.0" || it.Version == "26.6.4" {
			t.Errorf("item from %s is outside the upgrade", it.Version)
		}
	}

	if code, stdout, _ := run("upgrade", "--all", olderExport); code != ExitFindings || !strings.Contains(stdout, "Other notable changes (") {
		t.Errorf("--all: %d\n%s", code, stdout)
	}
}

func TestUpgradeNeedsAVersion(t *testing.T) {
	data, err := os.ReadFile(seedExport)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "keycloakVersion")
	out, _ := json.Marshal(doc)
	path := filepath.Join(t.TempDir(), "noversion.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run("upgrade", path); code != ExitUsage || !strings.Contains(stderr, "pass --from") {
		t.Errorf("without a version: %d %s", code, stderr)
	}
	if code, _, stderr := run("upgrade", "--from", "soon", path); code != ExitUsage || !strings.Contains(stderr, "not a Keycloak version") {
		t.Errorf("bad --from: %d %s", code, stderr)
	}
	if code, stdout, _ := run("upgrade", "--help"); code != ExitOK || !strings.Contains(stdout, "currently 26.8.0") {
		t.Errorf("help: %d %s", code, stdout)
	}
}
