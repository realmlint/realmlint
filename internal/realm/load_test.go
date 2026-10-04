package realm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures are real exports produced by scripts/gen-fixtures.sh from the
// seed realm in testdata/seed/acme-realm.json.
const fixtures = "../../testdata/realms"

var supportedVersions = []string{"26.8.0", "26.7.5", "26.6.4"}

func TestLoadSingleRealmFromEachSupportedVersion(t *testing.T) {
	for _, v := range supportedVersions {
		t.Run(v, func(t *testing.T) {
			realms, err := Load(filepath.Join(fixtures, v, "single.json"))
			if err != nil {
				t.Fatal(err)
			}
			if len(realms) != 1 {
				t.Fatalf("got %d realms, want 1", len(realms))
			}
			r := realms[0]
			if r.KeycloakVersion != v {
				t.Errorf("keycloakVersion = %q, want %q", r.KeycloakVersion, v)
			}
			assertAcme(t, r, 3)
		})
	}
}

func TestLoadAllRealmsFile(t *testing.T) {
	realms, err := Load(filepath.Join(fixtures, "26.8.0", "all.json"))
	if err != nil {
		t.Fatal(err)
	}
	names := realmNames(realms)
	if strings.Join(names, ",") != "master,acme" {
		t.Fatalf("realms = %v, want [master acme]", names)
	}
	assertAcme(t, realms[1], 3)
}

func TestLoadDirectoryMergesUsersFiles(t *testing.T) {
	realms, err := Load(filepath.Join(fixtures, "26.8.0", "dir"))
	if err != nil {
		t.Fatal(err)
	}
	if len(realms) != 1 {
		t.Fatalf("got %d realms, want 1", len(realms))
	}
	assertAcme(t, realms[0], 3)
}

func TestLoadSeveralPathsKeepsInputOrder(t *testing.T) {
	realms, err := Load(
		filepath.Join(fixtures, "26.8.0", "single.json"),
		writeFile(t, "other.json", `{"realm":"other"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(realmNames(realms), ","); got != "acme,other" {
		t.Fatalf("realms = %s, want acme,other", got)
	}
}

func TestLoadToleratesUnknownAndMissingFields(t *testing.T) {
	path := writeFile(t, "minimal.json", "\xEF\xBB\xBF"+`{
		"realm": "minimal",
		"someFutureSetting": {"nested": [1, 2, 3]},
		"attributes": {"flag": true, "count": 3, "name": "x", "empty": null},
		"clients": [{"clientId": "bare"}],
		"components": {"custom.Type": [{"name": "c", "config": {"single": "v", "list": ["a", "b"]}}]}
	}`)
	realms, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r := realms[0]

	wantAttrs := map[string]string{"flag": "true", "count": "3", "name": "x", "empty": ""}
	for k, want := range wantAttrs {
		if got := r.Attributes[k]; got != want {
			t.Errorf("attribute %s = %q, want %q", k, got, want)
		}
	}

	c := r.Clients[0]
	if !c.IsEnabled() || !c.UsesStandardFlow() || !c.HasFullScope() {
		t.Errorf("missing client fields should use Keycloak defaults (enabled, standard flow, full scope)")
	}

	cfg := r.ComponentsOf("custom.Type")[0].Config
	if cfg.First("single") != "v" || len(cfg["list"]) != 2 {
		t.Errorf("component config = %v, want single=[v] list=[a b]", cfg)
	}
}

func TestLoadErrors(t *testing.T) {
	emptyDir := t.TempDir()
	tests := []struct {
		name    string
		paths   []string
		wantErr string
	}{
		{"no paths", nil, "no realm export files"},
		{"missing file", []string{filepath.Join(t.TempDir(), "nope.json")}, "no such file"},
		{"empty directory", []string{emptyDir}, "contains no .json files"},
		{"empty file", []string{writeFile(t, "empty.json", "  ")}, "file is empty"},
		{"invalid JSON", []string{writeFile(t, "bad.json", `{"realm": `)}, "invalid JSON"},
		{"not JSON", []string{writeFile(t, "text.json", "realm: acme")}, "not a JSON object or array"},
		{"no realm name", []string{writeFile(t, "norealm.json", `{"clients": []}`)}, `missing "realm" name`},
		{"bad item in array", []string{writeFile(t, "arr.json", `[{"realm":"a"}, {}]`)}, "item 1"},
		{"wrong field type", []string{writeFile(t, "type.json", `{"realm":"a","clients":{}}`)}, "not a Keycloak realm export"},
		{
			"duplicate realm",
			[]string{writeFile(t, "a.json", `{"realm":"dup"}`), writeFile(t, "b.json", `{"realm":"dup"}`)},
			`realm "dup" is also defined in`,
		},
		{
			"users file without its realm",
			[]string{writeFile(t, "x-users-0.json", `{"realm":"x","users":[{"username":"u"}]}`)},
			`users file for realm "x"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.paths...)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// assertAcme checks the parts of the seed realm that later checks rely on.
func assertAcme(t *testing.T, r *Realm, wantUsers int) {
	t.Helper()
	if r.Realm != "acme" {
		t.Fatalf("realm = %q, want acme", r.Realm)
	}
	if r.SSLRequired != "none" || r.BruteForceProtected || r.AdminEventsEnabled {
		t.Errorf("realm settings not parsed: sslRequired=%q bruteForce=%v adminEvents=%v",
			r.SSLRequired, r.BruteForceProtected, r.AdminEventsEnabled)
	}
	if r.AccessTokenLifespan != 3600 || r.PasswordPolicy != "length(6)" {
		t.Errorf("accessTokenLifespan=%d passwordPolicy=%q", r.AccessTokenLifespan, r.PasswordPolicy)
	}

	clients := map[string]Client{}
	for _, c := range r.Clients {
		clients[c.ClientID] = c
	}
	spa, ok := clients["web-spa"]
	if !ok || !spa.PublicClient || !spa.ImplicitFlowEnabled || !spa.DirectAccessGrantsEnabled ||
		len(spa.RedirectURIs) != 1 || spa.RedirectURIs[0] != "*" {
		t.Errorf("web-spa not parsed as expected: %+v", spa)
	}
	if got := clients["mobile-app"].Attributes["pkce.code.challenge.method"]; got != "S256" {
		t.Errorf("mobile-app PKCE attribute = %q, want S256", got)
	}
	if billing := clients["billing-service"]; !billing.ServiceAccountsEnabled || !billing.HasFullScope() {
		t.Errorf("billing-service: serviceAccounts=%v fullScope=%v", billing.ServiceAccountsEnabled, billing.HasFullScope())
	}

	if len(r.Users) != wantUsers {
		t.Fatalf("got %d users, want %d", len(r.Users), wantUsers)
	}
	var serviceAccounts int
	for _, u := range r.Users {
		if u.IsServiceAccount() {
			serviceAccounts++
			if u.ClientRoles["realm-management"][0] != "realm-admin" {
				t.Errorf("service account roles = %v, want realm-management/realm-admin", u.ClientRoles)
			}
		}
	}
	if serviceAccounts != 1 {
		t.Errorf("got %d service accounts, want 1", serviceAccounts)
	}

	if len(r.Roles.Client["realm-management"]) == 0 {
		t.Errorf("client roles for realm-management not parsed")
	}
	if len(r.Groups) != 1 || len(r.Groups[0].SubGroups) != 1 || r.Groups[0].SubGroups[0].Path != "/staff/admins" {
		t.Errorf("groups not parsed as expected: %+v", r.Groups)
	}

	if len(r.IdentityProviders) != 1 || r.IdentityProviders[0].Config["validateSignature"] != "false" {
		t.Errorf("identity provider not parsed as expected: %+v", r.IdentityProviders)
	}

	keys := r.ComponentsOf(KeyProviderType)
	if len(keys) == 0 {
		t.Fatal("no key provider components")
	}
	var withCert int
	for _, k := range keys {
		if k.Config.First("certificate") != "" {
			withCert++
		}
	}
	if withCert == 0 {
		t.Errorf("no key provider has a certificate in its config")
	}
}

func realmNames(realms []*Realm) []string {
	names := make([]string, len(realms))
	for i, r := range realms {
		names[i] = r.Realm
	}
	return names
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
