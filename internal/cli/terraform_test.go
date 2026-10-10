package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestTerraformCheck(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run([]string{"terraform", "check", "../../pkg/terraform/testdata/plan-create.json"}, &out, &errOut)
	if code != ExitFindings || !strings.Contains(out.String(), "(keycloak_openid_client.web)") || !strings.Contains(out.String(), "Realm tfshop") {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errOut.String())
	}
	out.Reset()
	// The update plan only adds the reports client; with --new-only and
	// --min-severity high nothing new is high.
	code = Run([]string{"terraform", "check", "--new-only", "--min-severity", "high", "../../pkg/terraform/testdata/plan-update.json"}, &out, &errOut)
	if code != ExitOK {
		t.Fatalf("new-only high: exit %d\n%s", code, out.String())
	}
	if code := Run([]string{"terraform", "check", "../../testdata/realms/26.8.0/single.json"}, &out, &errOut); code != ExitUsage {
		t.Errorf("a realm export is not a plan: exit %d", code)
	}
}

func TestTerraformExport(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run([]string{"terraform", "export", "--realm", "acme", "../../testdata/realms/26.8.0/dir"}, &out, &errOut)
	if code != ExitOK || !strings.Contains(out.String(), `resource "keycloak_realm" "acme"`) || !strings.Contains(out.String(), "import {") {
		t.Fatalf("exit %d\n%.500s\n%s", code, out.String(), errOut.String())
	}
	if code := Run([]string{"terraform", "export", "--realm", "nope", "../../testdata/realms/26.8.0/dir"}, &out, &errOut); code != ExitUsage {
		t.Errorf("unknown realm: exit %d", code)
	}
}
