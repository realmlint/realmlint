package upgrade

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEveryCheckIsAGuideItem(t *testing.T) {
	anchors := map[string]bool{}
	for _, it := range Catalogue() {
		if it.Version == "" || it.Anchor == "" || it.Title == "" || it.Summary == "" {
			t.Errorf("incomplete item %+v", it)
		}
		if anchors[it.Anchor] {
			t.Errorf("duplicate anchor %s", it.Anchor)
		}
		anchors[it.Anchor] = true
	}
	for a := range checks {
		if !anchors[a] {
			t.Errorf("check %s has no item in the guide", a)
		}
	}
}

func TestVersions(t *testing.T) {
	v := Versions()
	if v[0] != "26.8.0" || v[len(v)-1] != Oldest {
		t.Fatalf("versions run %s..%s", v[0], v[len(v)-1])
	}
	for _, c := range []struct {
		a, b string
		want int
	}{{"26.4.10.redhat-00001", "26.4.2", 1}, {"26.4.2", "26.4.2", 0}, {"26.0", "26.0.6", -1}} {
		if got := Compare(c.a, c.b); (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("Compare(%s, %s) = %d", c.a, c.b, got)
		}
	}
	if _, ok := Parse("latest"); ok {
		t.Error("parsed latest")
	}
}

const shop = `{
 "realm": "shop", "registrationAllowed": true, "verifyEmail": true, "bruteForceProtected": true,
 "ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 36000,
 "clients": [
  {"clientId": "web", "enabled": true, "fullScopeAllowed": true,
   "redirectUris": ["https://shop.example.com*", "https://*", "/app/*"],
   "attributes": {"post.logout.redirect.uris": "https://shop.example.com/out?state=x##+",
     "exclude.issuer.from.auth.response": "true", "client.session.idle.timeout": "3600"}},
  {"clientId": "api", "bearerOnly": true, "fullScopeAllowed": true},
  {"clientId": "realm-management", "bearerOnly": true},
  {"clientId": "admin-cli", "fullScopeAllowed": true, "attributes": {"client.use.lightweight.access.token.enabled": "true"}},
  {"clientId": "old", "enabled": false, "fullScopeAllowed": false},
  {"clientId": "batch", "serviceAccountsEnabled": true, "fullScopeAllowed": false, "clientAuthenticatorType": "client-x509",
   "attributes": {"client_credentials.use_refresh_token": "true"}},
  {"clientId": "spa", "implicitFlowEnabled": true, "fullScopeAllowed": false,
   "attributes": {"dpop.bound.access.tokens": "true", "client.use.lightweight.access.token.enabled": "true"},
   "protocolMappers": [{"name": "krb", "config": {"user.session.note": "gss_delegation_credential"}}]}
 ],
 "identityProviders": [
  {"alias": "x", "providerId": "twitter", "config": {}},
  {"alias": "corp", "providerId": "oidc", "config": {"issuer": "https://idp", "clientAuthMethod": "client_secret_basic"}},
  {"alias": "corp2", "providerId": "oidc", "config": {"issuer": "https://idp"}}
 ],
 "groups": [{"name": "staff", "path": "/staff", "subGroups": [
   {"name": "ops", "path": "/staff/ops", "clientRoles": {"realm-management": ["view-system"]}, "subGroups": []}]}],
 "users": [{"username": "sam", "clientRoles": {"realm-management": ["view-system", "view-users"]}}],
 "clientPolicies": {"policies": [{"name": "updaters", "conditions": [
   {"condition": "client-updater-source-groups", "configuration": {"groups": ["staff", "ops"]}}]}]}
}`

func TestAdvise(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(shop))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	rep, err := Advise("26.0.0", "26.8.0", map[string]map[string]any{"shop": doc})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, a := range rep.Items {
		if a.Status == Affected {
			for _, h := range a.Hits {
				got[a.Anchor] = append(got[a.Anchor], h.Object+": "+h.Detail)
			}
		}
	}
	want := map[string][]string{
		"disabled-clients-are-no-longer-added-to-the-token-audience":                                          {"Client old"},
		"full-scope-allowed-switch-on-clients-is-deprecated":                                                  {"Client web"},
		"client-switches-in-the-openid-connect-compatibility-modes":                                           {"Client web: on: Exclude Issuer"},
		"use-refresh-tokens-for-client-credentials-grant-switch-on-clients-is-deprecated":                     {"Client batch"},
		"kerberos-credential-delegation-is-deprecated":                                                        {"Client spa"},
		"client-policy-source-groups-condition-matches-the-full-group-path":                                   {"Client policy updaters: group \"ops\""},
		"oidc-parameters-in-redirect-uris-rejected-by-default":                                                {"Client web: https://shop.example.com/out?state=x carries the state"},
		"x509-client-authentication-requires-ca-subject-dn":                                                   {"Client batch"},
		"the-view-system-admin-role-no-longer-exists":                                                         {"User sam", "Group /staff/ops"},
		"verify-email-required-before-credentials-setup-during-user-self-registration":                        {"Realm settings"},
		"dpop-not-supported-for-implicit-and-hybrid-flows":                                                    {"Client spa"},
		"switch-bearer-only-on-openid-connect-clients-is-deprecated":                                          {"Client api"},
		"twitter-identity-broker-deprecated-for-removal":                                                      {"Identity provider x"},
		"valid-redirect-uris-for-clients-do-not-accept-wildcards-for-hostname-anymore":                        {"Client web: https://shop.example.com*"},
		"userinfo-endpoint-rejects-lightweight-access-tokens":                                                 {"Client spa"},
		"new-brute-force-locking-mechanism":                                                                   {"Realm settings"},
		"the-identity-provider-issuer-should-be-unique-for-the-jwt-authorization-grant-and-client-assertions": {"Identity providers corp, corp2"},
		"validation-of-client-session-timeouts":                                                               {"Client web: Client Session Idle"},
		"corrected-encoding-when-sending-openid-connect-client-secrets-when-acting-as-a-broker":               {"Identity provider corp"},
	}
	for anchor, prefixes := range want {
		hits := got[anchor]
		if len(hits) != len(prefixes) {
			t.Errorf("%s: hits %q, want %d", anchor, hits, len(prefixes))
			continue
		}
		for i, p := range prefixes {
			if !strings.HasPrefix(hits[i], p) {
				t.Errorf("%s: hit %q, want prefix %q", anchor, hits[i], p)
			}
		}
	}
	for anchor, hits := range got {
		if _, ok := want[anchor]; !ok {
			t.Errorf("unexpected hits for %s: %q", anchor, hits)
		}
	}
	if rep.Items[0].Status != Affected {
		t.Error("affected items should come first")
	}
}

func TestAdviseRange(t *testing.T) {
	rep, err := Advise("26.6.3", "26.7.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rep.Items {
		if Compare(a.Version, "26.6.3") <= 0 || Compare(a.Version, "26.7.0") > 0 {
			t.Errorf("item %s from %s is outside the upgrade", a.Anchor, a.Version)
		}
		if a.Status == Affected || !strings.HasPrefix(a.URL, GuideURL+"#") {
			t.Errorf("item %+v", a)
		}
	}
	if len(rep.Items) == 0 {
		t.Fatal("no items")
	}
	if _, err := Advise("soon", "26.7.0", nil); err == nil {
		t.Error("accepted a bad version")
	}
}
