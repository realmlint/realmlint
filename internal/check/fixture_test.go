package check

import (
	"path/filepath"
	"testing"

	"github.com/edzordzinam/realmlint/internal/realm"
)

// The seed realm (testdata/seed/acme-realm.json) is misconfigured on
// purpose. These are the findings it must produce on every supported
// Keycloak version.
var seedFindings = []struct {
	check, object string
	severity      Severity
}{
	{"ssl-required-none", "", High},
	{"brute-force-disabled", "", Medium},
	{"weak-password-policy", "", Medium},
	{"login-events-disabled", "", Low},
	{"admin-events-disabled", "", Medium},
	{"long-access-token", "", Medium},
	{"long-sso-session", "", Medium},
	{"offline-sessions-unbounded", "", Low},
	{"redirect-uri-wildcard", `client "legacy-portal"`, Low},
	{"redirect-uri-wildcard", `client "web-spa"`, High},
	{"redirect-uri-http", `client "legacy-portal"`, Medium},
	{"web-origins-wildcard", `client "web-spa"`, Medium},
	{"implicit-flow-enabled", `client "web-spa"`, Medium},
	{"direct-access-grants", `client "web-spa"`, Medium},
	{"pkce-not-enforced", `client "web-spa"`, Medium},
	{"full-scope-allowed", `client "billing-service"`, Low},
	{"full-scope-allowed", `client "legacy-portal"`, Low},
	{"full-scope-allowed", `client "mobile-app"`, Low},
	{"full-scope-allowed", `client "web-spa"`, Low},
	{"service-account-admin", `service account of client "billing-service"`, High},
	{"admin-without-mfa", `user "alice"`, High},
	{"idp-signature-not-validated", `identity provider "partner-saml"`, High},
}

func TestSeedFixturesProduceExpectedFindings(t *testing.T) {
	for _, v := range []string{"26.8.0", "26.7.5", "26.6.4"} {
		t.Run(v, func(t *testing.T) {
			realms, err := realm.Load(filepath.Join("../../testdata/realms", v, "single.json"))
			if err != nil {
				t.Fatal(err)
			}
			got := map[[2]string]Severity{}
			for _, f := range Run(realms, All(), now) {
				got[[2]string{f.CheckID, f.Object}] = f.Severity
			}
			for _, w := range seedFindings {
				key := [2]string{w.check, w.object}
				sev, ok := got[key]
				switch {
				case !ok:
					t.Errorf("missing finding %s on %q", w.check, w.object)
				case sev != w.severity:
					t.Errorf("%s on %q: severity %s, want %s", w.check, w.object, sev, w.severity)
				}
				delete(got, key)
			}
			for key, sev := range got {
				t.Errorf("unexpected finding %s on %q (%s)", key[0], key[1], sev)
			}
		})
	}
}

func TestMasterRealmBuiltinsAreNotReported(t *testing.T) {
	realms, err := realm.Load("../../testdata/realms/26.8.0/all.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range Run(realms, All(), now) {
		if f.Realm == "master" && f.Object != "" {
			t.Errorf("unexpected finding on a master realm built-in: %s %s: %s", f.CheckID, f.Object, f.Message)
		}
	}
}
