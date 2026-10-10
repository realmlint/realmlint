package check

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/realmlint/realmlint/pkg/realm"
)

// builtinClients are created by Keycloak in every realm. Their defaults
// (for example admin-cli allowing password grants) are Keycloak's own, so
// client checks skip them.
var builtinClients = map[string]bool{
	"account":                true,
	"account-console":        true,
	"admin-cli":              true,
	"admin-permissions":      true,
	"broker":                 true,
	"realm-management":       true,
	"security-admin-console": true,
}

// isBuiltinClient also covers the "<realm>-realm" clients Keycloak creates in
// the master realm for each realm.
func isBuiltinClient(realmName, clientID string) bool {
	return builtinClients[clientID] || (realmName == "master" && strings.HasSuffix(clientID, "-realm"))
}

// appClients returns the enabled clients that are not Keycloak built-ins.
func appClients(r *realm.Realm) []*realm.Client {
	var out []*realm.Client
	for i := range r.Clients {
		c := &r.Clients[i]
		if c.IsEnabled() && !isBuiltinClient(r.Realm, c.ClientID) {
			out = append(out, c)
		}
	}
	return out
}

// redirectClients returns the app clients that can send a browser to a
// redirect URI: those with the standard or implicit flow on. Keycloak keeps
// (and hides) the redirect URIs of a client with both off, such as a service
// account client created with the default "/*", but never uses them.
func redirectClients(r *realm.Realm) []*realm.Client {
	var out []*realm.Client
	for _, c := range appClients(r) {
		if c.UsesStandardFlow() || c.ImplicitFlowEnabled {
			out = append(out, c)
		}
	}
	return out
}

var clientChecks = []Check{
	{
		ID:    "redirect-uri-wildcard",
		Title: "Redirect URIs use wildcards",
		Why:   "Keycloak sends authorization codes and tokens to the redirect URI. A wildcard lets an attacker choose where they go. A path wildcard on a fixed host is safer but still allows redirects to any page on that host.",
		Fix:   "In the client's Settings, replace wildcard Valid redirect URIs with the exact callback URLs.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for _, c := range redirectClients(ctx.Realm) {
				for _, uri := range c.RedirectURIs {
					if !strings.HasSuffix(uri, "*") {
						continue
					}
					if anyHostWildcard(uri) {
						findings = append(findings, Finding{
							Severity: High,
							Object:   clientObject(c),
							Message:  fmt.Sprintf("redirect URI %q allows any destination", uri),
						})
						continue
					}
					// Path wildcards on localhost are a development convenience.
					if isLoopback(uri) {
						continue
					}
					findings = append(findings, Finding{
						Severity: Low,
						Object:   clientObject(c),
						Message:  fmt.Sprintf("redirect URI %q allows any path", uri),
					})
				}
			}
			return findings
		},
	},
	{
		ID:    "redirect-uri-http",
		Title: "Redirect URIs use plain HTTP",
		Why:   "Authorization codes sent to an http:// redirect URI can be read on the network.",
		Fix:   "Change the redirect URI to https://. Plain HTTP is only acceptable for localhost during development.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for _, c := range redirectClients(ctx.Realm) {
				for _, uri := range c.RedirectURIs {
					if !strings.HasPrefix(strings.ToLower(uri), "http://") || isLoopback(uri) {
						continue
					}
					findings = append(findings, Finding{
						Severity: Medium,
						Object:   clientObject(c),
						Message:  fmt.Sprintf("redirect URI %q uses plain HTTP", uri),
					})
				}
			}
			return findings
		},
	},
	{
		ID:    "web-origins-wildcard",
		Title: "CORS allows any origin",
		Why:   `Web origin "*" lets JavaScript on any website call Keycloak endpoints for this client with the user's browser.`,
		Fix:   `In the client's Settings, replace "*" in Web origins with the exact origins, or "+" to allow only the redirect URI origins.`,
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for _, c := range appClients(ctx.Realm) {
				for _, o := range c.WebOrigins {
					if o == "*" {
						findings = append(findings, Finding{Severity: Medium, Object: clientObject(c), Message: `web origins include "*"`})
						break
					}
				}
			}
			return findings
		},
	},
	{
		ID:    "implicit-flow-enabled",
		Title: "Implicit flow is enabled",
		Why:   "The implicit flow returns tokens in the browser URL, where they leak through history, logs and referrer headers. OAuth 2.1 removes it.",
		Fix:   "Turn off Implicit flow in the client's Capability config and use the standard flow with PKCE.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for _, c := range appClients(ctx.Realm) {
				if c.ImplicitFlowEnabled {
					findings = append(findings, Finding{Severity: Medium, Object: clientObject(c), Message: "implicit flow is enabled"})
				}
			}
			return findings
		},
	},
	{
		ID:    "direct-access-grants",
		Title: "Password grant is enabled",
		Why:   "Direct access grants let an application collect the user's password itself, bypassing Keycloak's login page, second factors and brute-force protection. OAuth 2.1 removes this grant.",
		Fix:   "Turn off Direct access grants in the client's Capability config. Use the standard flow for users and client credentials for services.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for _, c := range appClients(ctx.Realm) {
				if !c.DirectAccessGrantsEnabled || c.BearerOnly {
					continue
				}
				sev, kind := Low, "confidential"
				if c.PublicClient {
					sev, kind = Medium, "public"
				}
				findings = append(findings, Finding{
					Severity: sev,
					Object:   clientObject(c),
					Message:  fmt.Sprintf("direct access grants are enabled on a %s client", kind),
				})
			}
			return findings
		},
	},
	{
		ID:    "pkce-not-enforced",
		Title: "Public client does not require PKCE",
		Why:   "Public clients have no secret, so without PKCE an intercepted authorization code can be exchanged for tokens by anyone.",
		Fix:   `In the client's Advanced tab, set Proof Key for Code Exchange Code Challenge Method to "S256".`,
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for _, c := range appClients(ctx.Realm) {
				if !c.PublicClient || !c.UsesStandardFlow() {
					continue
				}
				switch method := c.Attributes["pkce.code.challenge.method"]; method {
				case "S256":
				case "":
					findings = append(findings, Finding{Severity: Medium, Object: clientObject(c), Message: "PKCE is not required"})
				default:
					findings = append(findings, Finding{Severity: Medium, Object: clientObject(c), Message: fmt.Sprintf("PKCE method is %q instead of S256", method)})
				}
			}
			return findings
		},
	},
	{
		ID:    "full-scope-allowed",
		Title: "Tokens carry all of the user's roles",
		Why:   "With Full scope allowed, every token issued to the client contains all of the user's roles, including roles for other applications. A leaked token then grants more than this client needs.",
		Fix:   "In the client's Client scopes > Dedicated scope > Scope tab, turn off Full scope allowed and assign only the roles the client needs.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for _, c := range appClients(ctx.Realm) {
				if c.HasFullScope() && !c.BearerOnly {
					findings = append(findings, Finding{Severity: Low, Object: clientObject(c), Message: "full scope allowed is on"})
				}
			}
			return findings
		},
	},
}

// anyHostWildcard reports whether a redirect URI ending in "*" matches any
// host, such as "*", "/*" or "https://*".
func anyHostWildcard(uri string) bool {
	prefix := strings.TrimSuffix(uri, "*")
	if prefix == "" || prefix == "/" {
		return true
	}
	u, err := url.Parse(prefix)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host == ""
}

func isLoopback(uri string) bool {
	u, err := url.Parse(strings.TrimSuffix(uri, "*"))
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
