package check

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/edzordzinam/realmlint/internal/realm"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

// cleanRealm returns a realm that no check should report on. Each test case
// changes one thing about it.
func cleanRealm(t *testing.T) *realm.Realm {
	t.Helper()
	return &realm.Realm{
		Realm:                            "acme",
		Enabled:                          true,
		KeycloakVersion:                  "26.8.0",
		SSLRequired:                      "external",
		BruteForceProtected:              true,
		PasswordPolicy:                   "length(15) and notUsername",
		EventsEnabled:                    true,
		AdminEventsEnabled:               true,
		AdminEventsDetailsEnabled:        true,
		AccessTokenLifespan:              300,
		SSOSessionIdleTimeout:            1800,
		SSOSessionMaxLifespan:            36000,
		OfflineSessionIdleTimeout:        2592000,
		OfflineSessionMaxLifespanEnabled: true,
		OfflineSessionMaxLifespan:        5184000,
		Roles: realm.Roles{
			Realm: []realm.Role{{Name: "app-user"}},
			Client: map[string][]realm.Role{
				"realm-management": {{Name: "realm-admin"}, {Name: "view-users"}},
			},
		},
		Clients: []realm.Client{
			{
				ClientID: "portal", FullScopeAllowed: ptr(false),
				RedirectURIs: []string{"https://portal.acme.example/callback"},
				WebOrigins:   []string{"+"},
			},
			{
				ClientID: "spa", PublicClient: true, FullScopeAllowed: ptr(false),
				RedirectURIs: []string{"https://app.acme.example/callback", "http://localhost:3000/*"},
				Attributes:   realm.Attributes{"pkce.code.challenge.method": "S256"},
			},
			// Built-in clients with Keycloak's own defaults.
			{ClientID: "admin-cli", PublicClient: true, DirectAccessGrantsEnabled: true, StandardFlowEnabled: ptr(false)},
			{ClientID: "account", PublicClient: true, RedirectURIs: []string{"/realms/acme/account/*"}},
		},
		Users: []realm.User{
			{
				Username: "root", Enabled: true,
				ClientRoles: map[string][]string{"realm-management": {"realm-admin"}},
				Credentials: []realm.Credential{{Type: "password"}, {Type: "otp"}},
			},
			{Username: "bob", Enabled: true, RealmRoles: []string{"app-user"}},
		},
		IdentityProviders: []realm.IdentityProvider{{
			Alias: "partner", ProviderID: "saml", Enabled: true,
			Config: realm.Attributes{
				"validateSignature":  "true",
				"signingCertificate": testCert(t, now.AddDate(0, -1, 0), now.AddDate(1, 0, 0)),
			},
		}},
		Components: map[string][]realm.Component{
			realm.KeyProviderType: {
				{
					Name: "rsa-generated", ProviderID: "rsa-generated",
					Config: realm.MultiValue{"certificate": {testCert(t, now.AddDate(0, -1, 0), now.AddDate(10, 0, 0))}},
				},
				{Name: "hmac-generated", ProviderID: "hmac-generated", Config: realm.MultiValue{"algorithm": {"HS512"}}},
			},
		},
	}
}

func TestCleanRealmHasNoFindings(t *testing.T) {
	r := cleanRealm(t)
	if findings := Run([]*realm.Realm{r}, All(), now); len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("unexpected finding: %s %s %s: %s", f.CheckID, f.Severity, f.Object, f.Message)
		}
	}
}

func TestCheckIDsAreUniqueAndDocumented(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		if seen[c.ID] {
			t.Errorf("duplicate check ID %q", c.ID)
		}
		seen[c.ID] = true
		if c.Title == "" || c.Why == "" || c.Fix == "" || c.Run == nil {
			t.Errorf("check %q is missing a title, explanation, fix or run function", c.ID)
		}
	}
}

// want describes one expected finding. Object and message are matched as
// substrings.
type want struct {
	severity Severity
	object   string
	message  string
}

func TestChecks(t *testing.T) {
	tests := []struct {
		name   string
		check  string
		change func(r *realm.Realm)
		want   []want
	}{
		// ssl-required-none
		{"ssl none", "ssl-required-none", func(r *realm.Realm) { r.SSLRequired = "none" }, []want{{High, "", `"none"`}}},
		{"ssl all", "ssl-required-none", func(r *realm.Realm) { r.SSLRequired = "all" }, nil},

		// brute-force-disabled
		{"brute force off", "brute-force-disabled", func(r *realm.Realm) { r.BruteForceProtected = false }, []want{{Medium, "", "disabled"}}},

		// weak-password-policy
		{"no policy", "weak-password-policy", func(r *realm.Realm) { r.PasswordPolicy = "" }, []want{{Medium, "", "no password policy"}}},
		{"no length rule", "weak-password-policy", func(r *realm.Realm) { r.PasswordPolicy = "digits(1) and maxLength(64)" }, []want{{Medium, "", "no minimum length"}}},
		{"short length", "weak-password-policy", func(r *realm.Realm) { r.PasswordPolicy = "length(6)" }, []want{{Medium, "", "is 6"}}},
		{"length below recommendation", "weak-password-policy", func(r *realm.Realm) { r.PasswordPolicy = "digits(1) and length(10)" }, []want{{Low, "", "is 10"}}},

		// login-events-disabled
		{"login events off", "login-events-disabled", func(r *realm.Realm) { r.EventsEnabled = false }, []want{{Low, "", "not saved"}}},

		// admin-events-disabled
		{"admin events off", "admin-events-disabled", func(r *realm.Realm) { r.AdminEventsEnabled = false }, []want{{Medium, "", "not saved"}}},
		{"admin events without details", "admin-events-disabled", func(r *realm.Realm) { r.AdminEventsDetailsEnabled = false }, []want{{Low, "", "without the changed representation"}}},

		// master-realm-in-use
		{"app client in master", "master-realm-in-use", func(r *realm.Realm) {
			r.Realm = "master"
			r.Clients = append(r.Clients, realm.Client{ClientID: "acme-realm"}, realm.Client{ClientID: "master-realm"})
		}, []want{{Medium, `"portal"`, "master realm"}, {Medium, `"spa"`, "master realm"}}},
		{"only built-ins in master", "master-realm-in-use", func(r *realm.Realm) {
			r.Realm = "master"
			r.Clients = []realm.Client{{ClientID: "admin-cli"}, {ClientID: "acme-realm"}}
		}, nil},

		// long-access-token
		{"long realm access token", "long-access-token", func(r *realm.Realm) { r.AccessTokenLifespan = 3600 }, []want{{Medium, "", "1 hour"}}},
		{"long client override", "long-access-token", func(r *realm.Realm) {
			r.Clients[0].Attributes = realm.Attributes{"access.token.lifespan": "7200"}
		}, []want{{Medium, `"portal"`, "2 hours"}}},
		{"disabled client override ignored", "long-access-token", func(r *realm.Realm) {
			r.Clients[0].Attributes = realm.Attributes{"access.token.lifespan": "7200"}
			r.Clients[0].Enabled = ptr(false)
		}, nil},

		// long-sso-session
		{"long idle and max", "long-sso-session", func(r *realm.Realm) {
			r.SSOSessionIdleTimeout = 86400
			r.SSOSessionMaxLifespan = 30 * 86400
		}, []want{{Medium, "", "idle timeout is 1 day"}, {Medium, "", "max lifespan is 30 days"}}},

		// offline-sessions-unbounded
		{"offline unbounded, default idle", "offline-sessions-unbounded", func(r *realm.Realm) {
			r.OfflineSessionMaxLifespanEnabled = false
			r.OfflineSessionIdleTimeout = 0
		}, []want{{Low, "", "30 days without use"}}},

		// redirect-uri-wildcard
		{"star", "redirect-uri-wildcard", func(r *realm.Realm) { r.Clients[0].RedirectURIs = []string{"*"} }, []want{{High, `"portal"`, "any destination"}}},
		{"slash star", "redirect-uri-wildcard", func(r *realm.Realm) { r.Clients[0].RedirectURIs = []string{"/*"} }, []want{{High, "", "any destination"}}},
		{"scheme only", "redirect-uri-wildcard", func(r *realm.Realm) { r.Clients[0].RedirectURIs = []string{"https://*"} }, []want{{High, "", "any destination"}}},
		{"path wildcard", "redirect-uri-wildcard", func(r *realm.Realm) {
			r.Clients[0].RedirectURIs = []string{"https://portal.acme.example/*"}
		}, []want{{Low, `"portal"`, "any path"}}},
		{"built-in client ignored", "redirect-uri-wildcard", func(r *realm.Realm) { r.Clients[3].RedirectURIs = []string{"*"} }, nil},
		{"disabled client ignored", "redirect-uri-wildcard", func(r *realm.Realm) {
			r.Clients[0].RedirectURIs = []string{"*"}
			r.Clients[0].Enabled = ptr(false)
		}, nil},

		// redirect-uri-http
		{"http redirect", "redirect-uri-http", func(r *realm.Realm) {
			r.Clients[0].RedirectURIs = []string{"http://portal.acme.example/callback"}
		}, []want{{Medium, `"portal"`, "plain HTTP"}}},
		{"http loopback allowed", "redirect-uri-http", func(r *realm.Realm) {
			r.Clients[0].RedirectURIs = []string{"http://127.0.0.1:8080/cb", "http://localhost/cb"}
		}, nil},

		// web-origins-wildcard
		{"any origin", "web-origins-wildcard", func(r *realm.Realm) { r.Clients[1].WebOrigins = []string{"https://a.example", "*"} }, []want{{Medium, `"spa"`, `"*"`}}},

		// implicit-flow-enabled
		{"implicit on", "implicit-flow-enabled", func(r *realm.Realm) { r.Clients[1].ImplicitFlowEnabled = true }, []want{{Medium, `"spa"`, "implicit"}}},

		// direct-access-grants
		{"public client password grant", "direct-access-grants", func(r *realm.Realm) { r.Clients[1].DirectAccessGrantsEnabled = true }, []want{{Medium, `"spa"`, "public client"}}},
		{"confidential client password grant", "direct-access-grants", func(r *realm.Realm) { r.Clients[0].DirectAccessGrantsEnabled = true }, []want{{Low, `"portal"`, "confidential client"}}},

		// pkce-not-enforced
		{"pkce missing", "pkce-not-enforced", func(r *realm.Realm) { r.Clients[1].Attributes = nil }, []want{{Medium, `"spa"`, "not required"}}},
		{"pkce plain", "pkce-not-enforced", func(r *realm.Realm) {
			r.Clients[1].Attributes = realm.Attributes{"pkce.code.challenge.method": "plain"}
		}, []want{{Medium, `"spa"`, `"plain"`}}},
		{"confidential client without pkce", "pkce-not-enforced", func(r *realm.Realm) { r.Clients[0].Attributes = nil }, nil},

		// full-scope-allowed
		{"full scope by default", "full-scope-allowed", func(r *realm.Realm) { r.Clients[0].FullScopeAllowed = nil }, []want{{Low, `"portal"`, "full scope"}}},

		// service-account-admin
		{"service account with realm-admin", "service-account-admin", func(r *realm.Realm) {
			r.Users = append(r.Users, realm.User{
				Username: "service-account-billing", Enabled: true, ServiceAccountClientID: "billing",
				ClientRoles: map[string][]string{"realm-management": {"realm-admin"}},
			})
		}, []want{{High, `client "billing"`, "full realm admin"}}},
		{"service account admin through composite role", "service-account-admin", func(r *realm.Realm) {
			r.Roles.Realm = append(r.Roles.Realm, realm.Role{
				Name: "ops", Composite: true,
				Composites: &realm.Composites{Client: map[string][]string{"realm-management": {"realm-admin"}}},
			})
			r.Users = append(r.Users, realm.User{Username: "service-account-ops", Enabled: true, ServiceAccountClientID: "ops", RealmRoles: []string{"ops"}})
		}, []want{{High, `client "ops"`, ""}}},
		{"service account with narrow role", "service-account-admin", func(r *realm.Realm) {
			r.Users = append(r.Users, realm.User{
				Username: "service-account-sync", Enabled: true, ServiceAccountClientID: "sync",
				ClientRoles: map[string][]string{"realm-management": {"view-users"}},
			})
		}, nil},

		// admin-without-mfa
		{"admin without otp", "admin-without-mfa", func(r *realm.Realm) { r.Users[0].Credentials = []realm.Credential{{Type: "password"}} }, []want{{High, `user "root"`, "no OTP"}}},
		{"admin through parent group", "admin-without-mfa", func(r *realm.Realm) {
			r.Groups = []realm.Group{{
				Name: "staff", Path: "/staff",
				ClientRoles: map[string][]string{"realm-management": {"realm-admin"}},
				SubGroups:   []realm.Group{{Name: "ops", Path: "/staff/ops"}},
			}}
			r.Users = append(r.Users, realm.User{Username: "carol", Enabled: true, Groups: []string{"/staff/ops"}})
		}, []want{{High, `user "carol"`, ""}}},
		{"admin with pending otp setup", "admin-without-mfa", func(r *realm.Realm) {
			r.Users[0].Credentials = nil
			r.Users[0].RequiredActions = []string{"CONFIGURE_TOTP"}
		}, nil},
		{"admin with webauthn", "admin-without-mfa", func(r *realm.Realm) { r.Users[0].Credentials = []realm.Credential{{Type: "webauthn"}} }, nil},
		{"disabled admin", "admin-without-mfa", func(r *realm.Realm) {
			r.Users[0].Credentials = nil
			r.Users[0].Enabled = false
		}, nil},
		{"master admin role", "admin-without-mfa", func(r *realm.Realm) {
			r.Realm = "master"
			r.Roles.Realm = append(r.Roles.Realm, realm.Role{Name: "admin"})
			r.Users = append(r.Users, realm.User{Username: "boss", Enabled: true, RealmRoles: []string{"admin"}})
		}, []want{{High, `user "boss"`, ""}}},

		// temporary-admin-present
		{"temporary admin", "temporary-admin-present", func(r *realm.Realm) {
			r.Users = append(r.Users, realm.User{Username: "temp-admin", Enabled: true, Attributes: realm.MultiValue{"is_temporary_admin": {"true"}}})
		}, []want{{High, `user "temp-admin"`, "temporary"}}},

		// key-certificate-expiry
		{"expired key", "key-certificate-expiry", func(r *realm.Realm) {
			setKeyCert(t, r, now.AddDate(-2, 0, 0), now.AddDate(0, 0, -1))
		}, []want{{Critical, `key "rsa-generated"`, "expired"}}},
		{"key expiring soon", "key-certificate-expiry", func(r *realm.Realm) {
			setKeyCert(t, r, now.AddDate(0, -1, 0), now.AddDate(0, 0, 10))
		}, []want{{High, `key "rsa-generated"`, "in 10 days"}}},
		{"disabled expired key ignored", "key-certificate-expiry", func(r *realm.Realm) {
			setKeyCert(t, r, now.AddDate(-2, 0, 0), now.AddDate(0, 0, -1))
			r.Components[realm.KeyProviderType][0].Config["enabled"] = []string{"false"}
		}, nil},

		// key-not-rotated
		{"old key", "key-not-rotated", func(r *realm.Realm) {
			setKeyCert(t, r, now.AddDate(0, 0, -400), now.AddDate(9, 0, 0))
		}, []want{{Low, `key "rsa-generated"`, "400 days ago"}}},

		// idp-certificate-expiry
		{"one of two idp certs expiring", "idp-certificate-expiry", func(r *realm.Realm) {
			r.IdentityProviders[0].Config["signingCertificate"] =
				testCert(t, now.AddDate(-1, 0, 0), now.AddDate(0, 0, 5)) + "," + testCert(t, now, now.AddDate(1, 0, 0))
		}, []want{{High, `identity provider "partner"`, "in 5 days"}}},
		{"disabled idp ignored", "idp-certificate-expiry", func(r *realm.Realm) {
			r.IdentityProviders[0].Config["signingCertificate"] = testCert(t, now.AddDate(-1, 0, 0), now.AddDate(0, 0, -1))
			r.IdentityProviders[0].Enabled = false
		}, nil},

		// idp-signature-not-validated
		{"saml without validation", "idp-signature-not-validated", func(r *realm.Realm) {
			r.IdentityProviders[0].Config["validateSignature"] = "false"
		}, []want{{High, `identity provider "partner"`, "off"}}},
		{"oidc provider ignored", "idp-signature-not-validated", func(r *realm.Realm) {
			r.IdentityProviders[0].ProviderID = "oidc"
			delete(r.IdentityProviders[0].Config, "validateSignature")
		}, nil},

		// keycloak-version-outdated
		{"older minor", "keycloak-version-outdated", func(r *realm.Realm) { r.KeycloakVersion = "26.5.3" }, []want{{Medium, "", "26.5.3"}}},
		{"older major", "keycloak-version-outdated", func(r *realm.Realm) { r.KeycloakVersion = "25.0.6" }, []want{{Medium, "", "25.0.6"}}},
		{"oldest supported", "keycloak-version-outdated", func(r *realm.Realm) { r.KeycloakVersion = "26.6.0" }, nil},
		{"unknown version", "keycloak-version-outdated", func(r *realm.Realm) { r.KeycloakVersion = "" }, nil},
	}

	for _, tt := range tests {
		t.Run(tt.check+"/"+tt.name, func(t *testing.T) {
			r := cleanRealm(t)
			tt.change(r)
			got := Run([]*realm.Realm{r}, []Check{checkByID(t, tt.check)}, now)
			assertFindings(t, got, tt.want)
		})
	}
}

func TestOutdatedVersionReportedOncePerRun(t *testing.T) {
	a, b := cleanRealm(t), cleanRealm(t)
	a.KeycloakVersion, b.KeycloakVersion = "26.5.3", "26.5.3"
	b.Realm = "other"
	got := Run([]*realm.Realm{a, b}, []Check{checkByID(t, "keycloak-version-outdated")}, now)
	if len(got) != 1 || got[0].Realm != "acme" {
		t.Fatalf("got %d findings, want 1 on realm acme: %+v", len(got), got)
	}
}

func TestRunFillsCheckDetails(t *testing.T) {
	r := cleanRealm(t)
	r.SSLRequired = "none"
	r.Source = "exports/acme.json"
	got := Run([]*realm.Realm{r}, []Check{checkByID(t, "ssl-required-none")}, now)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.CheckID != "ssl-required-none" || f.Realm != "acme" || f.Source != "exports/acme.json" || f.Why == "" || f.Fix == "" {
		t.Errorf("finding missing check details: %+v", f)
	}
}

func TestHumanDuration(t *testing.T) {
	for in, want := range map[int]string{0: "0 seconds", 1: "1 second", 90: "90 seconds", 300: "5 minutes", 3600: "1 hour", 86400: "1 day", 2592000: "30 days"} {
		if got := humanDuration(in); got != want {
			t.Errorf("humanDuration(%d) = %q, want %q", in, got, want)
		}
	}
}

func checkByID(t *testing.T, id string) Check {
	t.Helper()
	for _, c := range All() {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check with ID %q", id)
	return Check{}
}

func assertFindings(t *testing.T, got []Finding, wants []want) {
	t.Helper()
	if len(got) != len(wants) {
		for _, f := range got {
			t.Logf("got: %s %s: %s", f.Severity, f.Object, f.Message)
		}
		t.Fatalf("got %d findings, want %d", len(got), len(wants))
	}
	for i, w := range wants {
		f := got[i]
		if f.Severity != w.severity || !strings.Contains(f.Object, w.object) || !strings.Contains(f.Message, w.message) {
			t.Errorf("finding %d = {%s, %q, %q}, want {%s, *%s*, *%s*}", i, f.Severity, f.Object, f.Message, w.severity, w.object, w.message)
		}
	}
}

func setKeyCert(t *testing.T, r *realm.Realm, notBefore, notAfter time.Time) {
	t.Helper()
	r.Components[realm.KeyProviderType][0].Config["certificate"] = []string{testCert(t, notBefore, notAfter)}
}

// testCert returns a self-signed certificate as Keycloak stores it: base64
// DER without PEM headers.
func testCert(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}
