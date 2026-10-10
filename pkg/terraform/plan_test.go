package terraform

import (
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/realmlint/realmlint/pkg/check"
	"github.com/realmlint/realmlint/pkg/realm"
)

// testdata/plan-create.json is terraform show -json of a real plan against
// Keycloak 26.8 with the keycloak/keycloak provider: a new realm with weak
// settings, a public client with wildcards and the implicit flow, a SAML
// provider without signature checks, and a service account given
// realm-admin.
func TestPlanFindings(t *testing.T) {
	data, err := os.ReadFile("testdata/plan-create.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePlan(data, "plan.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Before) != 0 || len(p.After) != 1 || p.After[0].Realm != "tfshop" || len(p.Unresolved) != 0 {
		t.Fatalf("realms after=%d before=%d unresolved=%v", len(p.After), len(p.Before), p.Unresolved)
	}
	got := map[string]string{}
	for _, f := range check.Run(p.After, Checks(), time.Now()) {
		got[f.CheckID+" "+f.Object] = p.AddressFor(f.Realm, f.Object, f.CheckID)
	}
	want := map[string]string{
		"ssl-required-none ":                                        "keycloak_realm.shop",
		"weak-password-policy ":                                     "keycloak_realm.shop",
		"long-access-token ":                                        "keycloak_realm.shop",
		"brute-force-disabled ":                                     "keycloak_realm.shop",
		"admin-events-disabled ":                                    "keycloak_realm_events.shop",
		`redirect-uri-wildcard client "web"`:                        "keycloak_openid_client.web",
		`implicit-flow-enabled client "web"`:                        "keycloak_openid_client.web",
		`idp-signature-not-validated identity provider "partner"`:   "keycloak_saml_identity_provider.partner",
		`service-account-admin service account of client "billing"`: "keycloak_openid_client_service_account_role.billing_admin",
	}
	for k, addr := range want {
		if a, ok := got[k]; !ok || a != addr {
			keys := make([]string, 0, len(got))
			for g, a := range got {
				keys = append(keys, g+" -> "+a)
			}
			sort.Strings(keys)
			t.Errorf("missing or misplaced %q (want %s); got:\n%s", k, addr, strings.Join(keys, "\n"))
		}
	}
	for k := range got {
		if strings.HasPrefix(k, "admin-without-mfa") || strings.HasPrefix(k, "key-") {
			t.Errorf("plan checks must not include %s", k)
		}
	}
}

func TestSeconds(t *testing.T) {
	for in, want := range map[any]int{"5m": 300, "1h0m0s": 3600, float64(60): 60} {
		if got, ok := seconds(in); !ok || got != want {
			t.Errorf("seconds(%v) = %d %v", in, got, ok)
		}
	}
	if _, ok := seconds(""); ok {
		t.Error("empty duration")
	}
}

// testdata/plan-update.json changes the applied configuration above: the
// web client's wildcard redirect is fixed and a new public client,
// "reports", uses the implicit flow.
func TestPlanNewFindings(t *testing.T) {
	data, err := os.ReadFile("testdata/plan-update.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePlan(data, "plan.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Before) != 1 {
		t.Fatalf("the update plan should carry the applied realm as before: %d", len(p.Before))
	}
	now := time.Now()
	fresh := NewFindings(check.Run(p.After, Checks(), now), check.Run(p.Before, Checks(), now))
	var got []string
	for _, f := range fresh {
		got = append(got, f.CheckID+" "+f.Object)
	}
	sort.Strings(got)
	joined := strings.Join(got, "\n")
	all := map[string]bool{}
	for _, f := range check.Run(p.After, Checks(), now) {
		all[f.CheckID+" "+f.Object] = true
	}
	if !all[`service-account-admin service account of client "billing"`] {
		t.Error("the unchanged realm-admin grant must still be found after the plan (data source from prior_state)")
	}
	if !strings.Contains(joined, `implicit-flow-enabled client "reports"`) {
		t.Errorf("the new client's implicit flow should be new:\n%s", joined)
	}
	for _, g := range got {
		if strings.Contains(g, `client "web"`) || strings.HasPrefix(g, "ssl-required-none") {
			t.Errorf("%s existed before the plan and is not new", g)
		}
	}
}

func TestExport(t *testing.T) {
	data, err := os.ReadFile("../../testdata/realms/26.8.0/dir/acme-realm.json")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := realm.Parse(data, "acme.json")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := Export(&b, rs); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{`resource "keycloak_realm" "acme"`, `resource "keycloak_realm_events" "acme"`, `import {`, `source  = "keycloak/keycloak"`} {
		if !strings.Contains(out, want) {
			t.Errorf("export missing %q", want)
		}
	}
	if strings.Contains(out, `client_id = "realm-management"`) {
		t.Error("built-in clients must not be exported")
	}
}

func TestQuote(t *testing.T) {
	if got := quote(`a "b" ${c} %{d}`); got != `"a \"b\" $${c} %%{d}"` {
		t.Errorf("quote = %s", got)
	}
}
