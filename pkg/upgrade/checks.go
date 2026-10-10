package upgrade

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// check finds the objects in one realm that a guide item affects. Each check
// keys off what the item says; attribute names are the ones Keycloak stores.
type check struct {
	looksAt string
	run     func(r realm) []Hit
}

var checks = map[string]check{
	// 26.8.0
	"disabled-clients-are-no-longer-added-to-the-token-audience": {"disabled clients", func(r realm) []Hit {
		return r.clientHits(func(c obj) string {
			if c.isFalse("enabled") {
				return "disabled: no longer in the aud claim of tokens, and its roles are left out of resource_access"
			}
			return ""
		})
	}},
	"full-scope-allowed-switch-on-clients-is-deprecated": {"Full scope allowed on clients", func(r realm) []Hit {
		return r.clientHits(func(c obj) string {
			if c.isTrue("fullScopeAllowed") && !c.isTrue("bearerOnly") && !builtIn(r.name, c.str("clientId")) {
				return "Full scope allowed is on"
			}
			return ""
		})
	}},
	"client-switches-in-the-openid-connect-compatibility-modes": {"OpenID Connect compatibility switches on clients", func(r realm) []Hit {
		switches := []struct{ attr, label string }{
			{"exclude.session.state.from.auth.response", "Exclude Session State From Authentication Response"},
			{"exclude.issuer.from.auth.response", "Exclude Issuer From Authentication Response"},
			{"token.response.type.bearer.lower-case", "Use lower-case bearer type in token responses"},
		}
		return r.clientHits(func(c obj) string {
			var on []string
			for _, s := range switches {
				if c.attr(s.attr) == "true" {
					on = append(on, s.label)
				}
			}
			if len(on) == 0 {
				return ""
			}
			return "on: " + strings.Join(on, ", ")
		})
	}},
	"use-refresh-tokens-for-client-credentials-grant-switch-on-clients-is-deprecated": {"service account clients", func(r realm) []Hit {
		return r.clientHits(func(c obj) string {
			if c.isTrue("serviceAccountsEnabled") && c.attr("client_credentials.use_refresh_token") == "true" {
				return "Use refresh tokens for client credentials grant is on"
			}
			return ""
		})
	}},
	"kerberos-credential-delegation-is-deprecated": {"client protocol mappers", func(r realm) []Hit {
		return r.clientHits(func(c obj) string {
			for _, m := range c.list("protocolMappers") {
				if m.obj("config").str("user.session.note") == "gss_delegation_credential" {
					return fmt.Sprintf("mapper %q adds the gss delegation credential", m.str("name"))
				}
			}
			return ""
		})
	}},
	// 26.7.x
	"client-policy-source-groups-condition-matches-the-full-group-path": {"client policy conditions", func(r realm) []Hit {
		top, sub := r.groupNames()
		var hits []Hit
		for _, p := range r.doc().obj("clientPolicies").list("policies") {
			for _, c := range p.list("conditions") {
				if c.str("condition") != "client-updater-source-groups" {
					continue
				}
				for _, g := range c.obj("configuration").strs("groups") {
					if !strings.HasPrefix(g, "/") && !top[g] && sub[g] {
						hits = append(hits, Hit{r.name, "Client policy " + p.str("name"),
							fmt.Sprintf("group %q is a subgroup: use its full path, such as %s", g, r.pathOf(g))})
					}
				}
			}
		}
		return hits
	}},
	"oidc-parameters-in-redirect-uris-rejected-by-default": {"redirect and post-logout redirect URIs", func(r realm) []Hit {
		return r.clientHits(func(c obj) string {
			for _, u := range append(c.strs("redirectUris"), c.split("post.logout.redirect.uris")...) {
				if p := oidcParam(u); p != "" {
					return fmt.Sprintf("%s carries the %s parameter", u, p)
				}
			}
			return ""
		})
	}},
	"x509-client-authentication-requires-ca-subject-dn": {"clients using X509 authentication", func(r realm) []Hit {
		return r.clientHits(func(c obj) string {
			if c.str("clientAuthenticatorType") == "client-x509" && c.attr("x509.casubjectdn") == "" {
				return "X509 authentication without a Certificate Authority subject DN"
			}
			return ""
		})
	}},
	"the-view-system-admin-role-no-longer-exists": {"users and groups holding view-system", func(r realm) []Hit {
		var hits []Hit
		has := func(o obj) bool {
			for _, roles := range o.obj("clientRoles") {
				for _, role := range asStrs(roles) {
					if role == "view-system" {
						return true
					}
				}
			}
			return false
		}
		for _, u := range r.doc().list("users") {
			if has(u) {
				hits = append(hits, Hit{r.name, "User " + u.str("username"), "holds view-system"})
			}
		}
		r.eachGroup(func(g obj) {
			if has(g) {
				hits = append(hits, Hit{r.name, "Group " + g.str("path"), "grants view-system"})
			}
		})
		return hits
	}},
	"verify-email-required-before-credentials-setup-during-user-self-registration": {"registration with Verify email", func(r realm) []Hit {
		d := r.doc()
		if d.isTrue("registrationAllowed") && d.isTrue("verifyEmail") {
			return []Hit{{r.name, "Realm settings", "registration and Verify email are both on: new users set a password after verifying"}}
		}
		return nil
	}},
	"dpop-not-supported-for-implicit-and-hybrid-flows": {"clients requiring DPoP", func(r realm) []Hit {
		return r.clientHits(func(c obj) string {
			if c.attr("dpop.bound.access.tokens") == "true" && c.isTrue("implicitFlowEnabled") {
				return "requires DPoP and allows the implicit flow"
			}
			return ""
		})
	}},
	"switch-bearer-only-on-openid-connect-clients-is-deprecated": {"bearer-only clients", func(r realm) []Hit {
		return r.clientHits(func(c obj) string {
			if c.isTrue("bearerOnly") && c.str("protocol") != "saml" && !builtIn(r.name, c.str("clientId")) {
				return "Bearer only is on"
			}
			return ""
		})
	}},
	"twitter-identity-broker-deprecated-for-removal": providerCheck("twitter"),
	// 26.6.x
	"valid-redirect-uris-for-clients-do-not-accept-wildcards-for-hostname-anymore": {"valid redirect URIs", func(r realm) []Hit {
		return r.clientHits(func(c obj) string {
			for _, u := range c.strs("redirectUris") {
				if hostWildcard.MatchString(u) {
					return u + " has a wildcard in the hostname"
				}
			}
			return ""
		})
	}},
	"userinfo-endpoint-rejects-lightweight-access-tokens": {"clients issuing lightweight access tokens", func(r realm) []Hit {
		return r.clientHits(func(c obj) string {
			if c.attr("client.use.lightweight.access.token.enabled") == "true" && !builtIn(r.name, c.str("clientId")) {
				return "Always use lightweight access token is on"
			}
			return ""
		})
	}},
	"stricter-validation-for-client-uris-secure-client-uris": {"client URIs under client policies", func(r realm) []Hit {
		if len(r.doc().obj("clientPolicies").list("policies")) == 0 {
			return nil
		}
		fields := []struct{ attr, label string }{{"logoUri", "Logo URL"}, {"policyUri", "Policy URL"}, {"tosUri", "Terms of service URL"}}
		return r.clientHits(func(c obj) string {
			for _, u := range c.split("post.logout.redirect.uris") {
				if strings.HasPrefix(u, "http://") {
					return "post logout redirect URI " + u + " uses http"
				}
			}
			for _, f := range fields {
				if strings.HasPrefix(c.attr(f.attr), "http://") {
					return f.label + " uses http"
				}
			}
			return ""
		})
	}},
	"new-brute-force-locking-mechanism": {"brute force detection", func(r realm) []Hit {
		if r.doc().isTrue("bruteForceProtected") {
			return []Hit{{r.name, "Realm settings", "brute force detection is on"}}
		}
		return nil
	}},
	"the-identity-provider-issuer-should-be-unique-for-the-jwt-authorization-grant-and-client-assertions": {"identity provider issuers", func(r realm) []Hit {
		byIssuer := map[string][]string{}
		for _, p := range r.doc().list("identityProviders") {
			if iss := p.obj("config").str("issuer"); iss != "" {
				byIssuer[iss] = append(byIssuer[iss], p.str("alias"))
			}
		}
		var hits []Hit
		for iss, aliases := range byIssuer {
			if len(aliases) > 1 {
				sort.Strings(aliases)
				hits = append(hits, Hit{r.name, "Identity providers " + strings.Join(aliases, ", "), "share the issuer " + iss})
			}
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].Object < hits[j].Object })
		return hits
	}},
	// 26.5.x
	"validation-of-client-session-timeouts": {"client session timeouts", func(r realm) []Hit {
		d := r.doc()
		ssoIdle, ssoMax := d.num("ssoSessionIdleTimeout"), d.num("ssoSessionMaxLifespan")
		var hits []Hit
		if v := d.num("clientSessionIdleTimeout"); v > 0 && ssoIdle > 0 && v > ssoIdle {
			hits = append(hits, Hit{r.name, "Realm settings", "Client Session Idle is longer than SSO Session Idle"})
		}
		if v := d.num("clientSessionMaxLifespan"); v > 0 && ssoMax > 0 && v > ssoMax {
			hits = append(hits, Hit{r.name, "Realm settings", "Client Session Max is longer than SSO Session Max"})
		}
		return append(hits, r.clientHits(func(c obj) string {
			if v := c.attrNum("client.session.idle.timeout"); v > 0 && ssoIdle > 0 && v > ssoIdle {
				return "Client Session Idle is longer than the realm's SSO Session Idle"
			}
			if v := c.attrNum("client.session.max.lifespan"); v > 0 && ssoMax > 0 && v > ssoMax {
				return "Client Session Max is longer than the realm's SSO Session Max"
			}
			return ""
		})...)
	}},
	// 26.4.x and earlier
	"corrected-encoding-when-sending-openid-connect-client-secrets-when-acting-as-a-broker": {"OpenID Connect identity providers", func(r realm) []Hit {
		var hits []Hit
		for _, p := range r.doc().list("identityProviders") {
			if p.obj("config").str("clientAuthMethod") == "client_secret_basic" {
				hits = append(hits, Hit{r.name, "Identity provider " + p.str("alias"),
					"sends the client secret with HTTP Basic: now URL-encoded, which matters if the client ID or secret has characters such as : or %"})
			}
		}
		return hits
	}},
	"jwt-client-authentication-aligned-with-the-latest-oidc-specification": {"clients using signed JWT authentication", func(r realm) []Hit {
		return r.clientHits(func(c obj) string {
			switch c.str("clientAuthenticatorType") {
			case "client-jwt", "client-secret-jwt":
				return "authenticates with a signed JWT: the assertion must carry a single audience"
			}
			return ""
		})
	}},
	"deprecated-for-removal-the-instagram-identity-broker": providerCheck("instagram"),
}

func providerCheck(providerID string) check {
	return check{providerID + " identity providers", func(r realm) []Hit {
		var hits []Hit
		for _, p := range r.doc().list("identityProviders") {
			if p.str("providerId") == providerID {
				hits = append(hits, Hit{r.name, "Identity provider " + p.str("alias"), "uses the " + providerID + " broker"})
			}
		}
		return hits
	}}
}

// hostWildcard matches a wildcard straight after hostname characters, as in
// https://example.com*; https://* alone is still accepted.
var hostWildcard = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^/*?#]+\*`)

// oidcParam returns the OIDC response parameter a redirect URI carries in
// its query or fragment, if any.
func oidcParam(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	for _, part := range []string{u.RawQuery, u.Fragment} {
		q, err := url.ParseQuery(part)
		if err != nil {
			continue
		}
		for _, p := range []string{"state", "code", "session_state"} {
			if _, ok := q[p]; ok {
				return p
			}
		}
	}
	return ""
}

// builtIn reports the clients Keycloak creates in every realm (and the
// per-realm clients in master); Keycloak sets their switches itself.
func builtIn(realmName, clientID string) bool {
	switch clientID {
	case "account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console":
		return true
	}
	return realmName == "master" && strings.HasSuffix(clientID, "-realm")
}

// realm is one snapshot, in the shape of kc.sh export.
type realm struct {
	name string
	data map[string]any
}

func (r realm) doc() obj { return obj(r.data) }

func (r realm) clientHits(f func(c obj) string) []Hit {
	var hits []Hit
	for _, c := range r.doc().list("clients") {
		if detail := f(c); detail != "" {
			hits = append(hits, Hit{r.name, "Client " + c.str("clientId"), detail})
		}
	}
	return hits
}

func (r realm) eachGroup(f func(g obj)) {
	var walk func(gs []obj)
	walk = func(gs []obj) {
		for _, g := range gs {
			f(g)
			walk(g.list("subGroups"))
		}
	}
	walk(r.doc().list("groups"))
}

func (r realm) groupNames() (top, sub map[string]bool) {
	top, sub = map[string]bool{}, map[string]bool{}
	for _, g := range r.doc().list("groups") {
		top[g.str("name")] = true
	}
	r.eachGroup(func(g obj) {
		if strings.Count(g.str("path"), "/") > 1 {
			sub[g.str("name")] = true
		}
	})
	return top, sub
}

func (r realm) pathOf(name string) string {
	path := ""
	r.eachGroup(func(g obj) {
		if path == "" && g.str("name") == name && strings.Count(g.str("path"), "/") > 1 {
			path = g.str("path")
		}
	})
	return path
}

// obj reads a JSON object without type assertions at every step.
type obj map[string]any

func (o obj) str(k string) string {
	s, _ := o[k].(string)
	return s
}

func (o obj) isTrue(k string) bool  { b, ok := o[k].(bool); return ok && b }
func (o obj) isFalse(k string) bool { b, ok := o[k].(bool); return ok && !b }

// num reads a number decoded either as float64 or as json.Number.
func (o obj) num(k string) float64 {
	switch n := o[k].(type) {
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}

func (o obj) obj(k string) obj {
	m, _ := o[k].(map[string]any)
	return obj(m)
}

func (o obj) list(k string) []obj {
	l, _ := o[k].([]any)
	out := make([]obj, 0, len(l))
	for _, v := range l {
		if m, ok := v.(map[string]any); ok {
			out = append(out, obj(m))
		}
	}
	return out
}

func (o obj) strs(k string) []string { return asStrs(o[k]) }

func (o obj) attr(k string) string { return o.obj("attributes").str(k) }

func (o obj) attrNum(k string) float64 {
	n, _ := strconv.ParseFloat(o.attr(k), 64)
	return n
}

// split reads a multi-valued client attribute, stored joined with "##".
func (o obj) split(k string) []string {
	var out []string
	for _, v := range strings.Split(o.attr(k), "##") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func asStrs(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
