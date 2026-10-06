package check

import (
	"path/filepath"
	"testing"

	"github.com/realmlint/realmlint/internal/realm"
)

// The seed realm (testdata/seed/acme-realm.json) is misconfigured on
// purpose. These are the findings it must produce on every supported
// Keycloak version, one entry per finding.
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
	{"long-sso-session", "", Medium}, // idle timeout
	{"long-sso-session", "", Medium}, // max lifespan
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
			type key struct {
				check, object string
				severity      Severity
			}
			got := map[key]int{}
			for _, f := range Run(realms, All(), now) {
				got[key{f.CheckID, f.Object, f.Severity}]++
			}
			for _, w := range seedFindings {
				k := key{w.check, w.object, w.severity}
				if got[k] == 0 {
					t.Errorf("missing %s finding %s on %q", w.severity, w.check, w.object)
					continue
				}
				got[k]--
			}
			for k, n := range got {
				if n > 0 {
					t.Errorf("unexpected %s finding %s on %q (x%d)", k.severity, k.check, k.object, n)
				}
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
