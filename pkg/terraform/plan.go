// Package terraform reads Terraform plans for the keycloak/keycloak
// provider and writes Terraform configuration from realm exports.
//
// A plan (terraform show -json) is turned into realm representations, so the
// same checks that run on exports can run before terraform apply. Only
// what Terraform declares is known, so only checks whose inputs Terraform
// declares are run (see Checks).
package terraform

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/realmlint/realmlint/pkg/check"
	"github.com/realmlint/realmlint/pkg/realm"
)

// Plan is a Terraform plan turned into realms.
type Plan struct {
	// After is the configuration the plan would apply; Before is what
	// Terraform managed before the plan (empty for a first apply).
	After, Before []*realm.Realm
	// Addresses maps a realm and finding object (as checks print it) to
	// the Terraform resource that declares it.
	Addresses map[string]string
	// Unresolved lists resources whose realm could not be worked out.
	Unresolved []string
}

// AddressFor returns the resource that declares an object of a realm.
// Realm-wide findings ("" object) map to the realm resource.
func (p *Plan) AddressFor(realmName, object, checkID string) string {
	if object == "" && strings.Contains(checkID, "events") {
		if a, ok := p.Addresses[realmName+"\x00events"]; ok {
			return a
		}
	}
	return p.Addresses[realmName+"\x00"+object]
}

// checkIDs are the checks whose inputs a plan declares. Credentials, keys,
// versions and live users are not in Terraform, so their checks would only
// produce noise.
var checkIDs = map[string]bool{
	"ssl-required-none": true, "brute-force-disabled": true, "weak-password-policy": true,
	"login-events-disabled": true, "admin-events-disabled": true,
	"long-access-token": true, "long-sso-session": true, "offline-sessions-unbounded": true,
	"redirect-uri-wildcard": true, "redirect-uri-http": true, "web-origins-wildcard": true,
	"implicit-flow-enabled": true, "direct-access-grants": true, "pkce-not-enforced": true,
	"full-scope-allowed": true, "idp-signature-not-validated": true, "service-account-admin": true,
	"master-realm-in-use": true,
}

// Checks returns the checks that apply to Terraform plans.
func Checks() []check.Check {
	var out []check.Check
	for _, c := range check.All() {
		if checkIDs[c.ID] {
			out = append(out, c)
		}
	}
	return out
}

type jsonPlan struct {
	FormatVersion string `json:"format_version"`
	PlannedValues struct {
		RootModule module `json:"root_module"`
	} `json:"planned_values"`
	// PriorState holds data sources Terraform read while planning; they
	// are not repeated in planned_values.
	PriorState struct {
		Values struct {
			RootModule module `json:"root_module"`
		} `json:"values"`
	} `json:"prior_state"`
	ResourceChanges []struct {
		Address string `json:"address"`
		Mode    string `json:"mode"`
		Type    string `json:"type"`
		Change  struct {
			Actions []string       `json:"actions"`
			Before  map[string]any `json:"before"`
		} `json:"change"`
	} `json:"resource_changes"`
	Configuration struct {
		RootModule configModule `json:"root_module"`
	} `json:"configuration"`
}

type module struct {
	Address      string   `json:"address"`
	Resources    []res    `json:"resources"`
	ChildModules []module `json:"child_modules"`
}

type res struct {
	Address string         `json:"address"`
	Mode    string         `json:"mode"`
	Type    string         `json:"type"`
	Values  map[string]any `json:"values"`
}

type configModule struct {
	Resources []struct {
		Address     string                `json:"address"`
		Expressions map[string]expression `json:"expressions"`
	} `json:"resources"`
	ModuleCalls map[string]struct {
		Module configModule `json:"module"`
	} `json:"module_calls"`
}

type expression struct {
	References []string `json:"references"`
}

// ParsePlan reads the JSON of terraform show -json for a saved plan.
func ParsePlan(data []byte, source string) (*Plan, error) {
	var jp jsonPlan
	if err := json.Unmarshal(data, &jp); err != nil {
		return nil, fmt.Errorf("%s: not a Terraform plan in JSON: %w", source, err)
	}
	if jp.FormatVersion == "" {
		return nil, fmt.Errorf("%s: not a Terraform plan in JSON; create one with: terraform show -json plan.out", source)
	}
	refs := map[string]map[string][]string{}
	collectRefs(jp.Configuration.RootModule, "", refs)

	var after []res
	flatten(jp.PlannedValues.RootModule, &after)
	var before []res
	dataSources := map[string]res{}
	var prior []res
	flatten(jp.PriorState.Values.RootModule, &prior)
	for _, r := range append(prior, after...) {
		if r.Mode == "data" {
			dataSources[r.Address] = r
		}
	}
	// Data sources only in the prior state are needed after the plan too.
	for addr, r := range dataSources {
		found := false
		for _, a := range after {
			if a.Address == addr {
				found = true
				break
			}
		}
		if !found {
			after = append(after, r)
		}
	}
	for _, c := range jp.ResourceChanges {
		if c.Mode == "managed" && c.Change.Before != nil {
			before = append(before, res{Address: c.Address, Mode: c.Mode, Type: c.Type, Values: c.Change.Before})
		}
	}
	for _, r := range dataSources {
		before = append(before, r)
	}

	p := &Plan{Addresses: map[string]string{}}
	var err error
	if p.After, err = build(after, refs, source, p.Addresses, &p.Unresolved); err != nil {
		return nil, err
	}
	if p.Before, err = build(before, refs, source, map[string]string{}, new([]string)); err != nil {
		return nil, err
	}
	return p, nil
}

func flatten(m module, out *[]res) {
	*out = append(*out, m.Resources...)
	for _, c := range m.ChildModules {
		flatten(c, out)
	}
}

// collectRefs records each resource attribute's references, with module
// addresses prefixed so they match planned values.
func collectRefs(m configModule, prefix string, out map[string]map[string][]string) {
	for _, r := range m.Resources {
		addr := prefix + r.Address
		out[addr] = map[string][]string{}
		for attr, e := range r.Expressions {
			for _, ref := range e.References {
				out[addr][attr] = append(out[addr][attr], prefix+ref)
			}
		}
	}
	names := make([]string, 0, len(m.ModuleCalls))
	for n := range m.ModuleCalls {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		collectRefs(m.ModuleCalls[n].Module, prefix+"module."+n+".", out)
	}
}

type builder struct {
	byAddr     map[string]res
	refs       map[string]map[string][]string
	realms     map[string]map[string]any
	order      []string
	addresses  map[string]string
	unresolved *[]string
}

func build(resources []res, refs map[string]map[string][]string, source string, addresses map[string]string, unresolved *[]string) ([]*realm.Realm, error) {
	b := &builder{byAddr: map[string]res{}, refs: refs, realms: map[string]map[string]any{}, addresses: addresses, unresolved: unresolved}
	for _, r := range resources {
		b.byAddr[r.Address] = r
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].Address < resources[j].Address })
	// Realms first, so other resources can find them.
	for _, r := range resources {
		if r.Mode == "managed" && r.Type == "keycloak_realm" {
			b.addRealm(r)
		}
	}
	for _, r := range resources {
		if r.Mode != "managed" {
			continue
		}
		switch r.Type {
		case "keycloak_realm_events":
			b.addEvents(r)
		case "keycloak_openid_client":
			b.addClient(r)
		case "keycloak_saml_identity_provider", "keycloak_oidc_identity_provider":
			b.addProvider(r)
		case "keycloak_openid_client_service_account_role":
			b.addServiceAccountRole(r)
		case "keycloak_user":
			b.addUser(r)
		}
	}
	var out []*realm.Realm
	for _, name := range b.order {
		data, err := json.Marshal(b.realms[name])
		if err != nil {
			return nil, err
		}
		rs, err := realm.Parse(data, source)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}

// realmOf finds the realm a resource belongs to: a known realm name, or the
// keycloak_realm resource it references.
func (b *builder) realmOf(r res, attr string) (string, bool) {
	if s, ok := r.Values[attr].(string); ok && s != "" {
		// The provider's realm ID is the realm name.
		return b.ensure(s), true
	}
	for _, ref := range b.refs[r.Address][attr] {
		addr := strings.TrimSuffix(ref, ".id")
		if t, ok := b.byAddr[addr]; ok && t.Type == "keycloak_realm" {
			if name, ok := t.Values["realm"].(string); ok && name != "" {
				return b.ensure(name), true
			}
		}
	}
	*b.unresolved = append(*b.unresolved, r.Address)
	return "", false
}

func (b *builder) ensure(name string) string {
	if _, ok := b.realms[name]; !ok {
		b.realms[name] = map[string]any{"realm": name, "enabled": true}
		b.order = append(b.order, name)
	}
	return name
}

func (b *builder) addRealm(r res) {
	name, _ := r.Values["realm"].(string)
	if name == "" {
		*b.unresolved = append(*b.unresolved, r.Address)
		return
	}
	d := b.realms[b.ensure(name)]
	b.addresses[name+"\x00"] = r.Address
	copyBool(r.Values, "enabled", d, "enabled")
	copyString(r.Values, "ssl_required", d, "sslRequired")
	copyString(r.Values, "password_policy", d, "passwordPolicy")
	copyBool(r.Values, "registration_allowed", d, "registrationAllowed")
	copyBool(r.Values, "verify_email", d, "verifyEmail")
	copyBool(r.Values, "offline_session_max_lifespan_enabled", d, "offlineSessionMaxLifespanEnabled")
	copySeconds(r.Values, "access_token_lifespan", d, "accessTokenLifespan")
	copySeconds(r.Values, "sso_session_idle_timeout", d, "ssoSessionIdleTimeout")
	copySeconds(r.Values, "sso_session_max_lifespan", d, "ssoSessionMaxLifespan")
	copySeconds(r.Values, "offline_session_max_lifespan", d, "offlineSessionMaxLifespan")
	// Brute force detection is on when its block is present.
	if bf := firstBlock(firstBlock(r.Values["security_defenses"])["brute_force_detection"]); bf != nil {
		d["bruteForceProtected"] = true
		copyBool(bf, "permanent_lockout", d, "permanentLockout")
		if n, ok := bf["max_login_failures"].(float64); ok {
			d["failureFactor"] = int(n)
		}
	}
}

func (b *builder) addEvents(r res) {
	name, ok := b.realmOf(r, "realm_id")
	if !ok {
		return
	}
	d := b.realms[name]
	b.addresses[name+"\x00events"] = r.Address
	copyBool(r.Values, "events_enabled", d, "eventsEnabled")
	copyBool(r.Values, "admin_events_enabled", d, "adminEventsEnabled")
	copyBool(r.Values, "admin_events_details_enabled", d, "adminEventsDetailsEnabled")
}

func (b *builder) addClient(r res) {
	name, ok := b.realmOf(r, "realm_id")
	if !ok {
		return
	}
	id, _ := r.Values["client_id"].(string)
	if id == "" {
		return
	}
	c := map[string]any{"clientId": id, "protocol": "openid-connect"}
	copyBool(r.Values, "enabled", c, "enabled")
	switch r.Values["access_type"] {
	case "PUBLIC":
		c["publicClient"] = true
	case "BEARER-ONLY":
		c["bearerOnly"] = true
	}
	copyBool(r.Values, "standard_flow_enabled", c, "standardFlowEnabled")
	copyBool(r.Values, "implicit_flow_enabled", c, "implicitFlowEnabled")
	copyBool(r.Values, "direct_access_grants_enabled", c, "directAccessGrantsEnabled")
	copyBool(r.Values, "service_accounts_enabled", c, "serviceAccountsEnabled")
	copyBool(r.Values, "full_scope_allowed", c, "fullScopeAllowed")
	copyString(r.Values, "root_url", c, "rootUrl")
	copyString(r.Values, "base_url", c, "baseUrl")
	c["redirectUris"] = stringList(r.Values["valid_redirect_uris"])
	c["webOrigins"] = stringList(r.Values["web_origins"])
	attrs := map[string]any{}
	if m, ok := r.Values["pkce_code_challenge_method"].(string); ok && m != "" {
		attrs["pkce.code.challenge.method"] = m
	}
	if s, ok := seconds(r.Values["access_token_lifespan"]); ok {
		attrs["access.token.lifespan"] = strconv.Itoa(s)
	}
	c["attributes"] = attrs
	appendTo(b.realms[name], "clients", c)
	b.addresses[name+"\x00"+fmt.Sprintf("client %q", id)] = r.Address
}

func (b *builder) addProvider(r res) {
	name, ok := b.realmOf(r, "realm")
	if !ok {
		return
	}
	alias, _ := r.Values["alias"].(string)
	if alias == "" {
		return
	}
	provider := "oidc"
	if r.Type == "keycloak_saml_identity_provider" {
		provider = "saml"
	}
	enabled := true
	if v, ok := r.Values["enabled"].(bool); ok {
		enabled = v
	}
	cfg := map[string]any{}
	if v, ok := r.Values["validate_signature"].(bool); ok {
		cfg["validateSignature"] = strconv.FormatBool(v)
	}
	appendTo(b.realms[name], "identityProviders", map[string]any{"alias": alias, "providerId": provider, "enabled": enabled, "config": cfg})
	b.addresses[name+"\x00"+fmt.Sprintf("identity provider %q", alias)] = r.Address
}

// addServiceAccountRole gives a client's service account a client role, so
// service-account-admin sees realm-admin granted in Terraform.
func (b *builder) addServiceAccountRole(r res) {
	name, ok := b.realmOf(r, "realm_id")
	if !ok {
		return
	}
	role, _ := r.Values["role"].(string)
	owner := b.clientIDOf(r, "service_account_user_id")
	roleClient := b.clientIDOf(r, "client_id")
	if role == "" || owner == "" || roleClient == "" {
		return
	}
	user := "service-account-" + owner
	d := b.realms[name]
	users, _ := d["users"].([]any)
	for _, u := range users {
		m := u.(map[string]any)
		if m["username"] == user {
			cr := m["clientRoles"].(map[string]any)
			list, _ := cr[roleClient].([]any)
			cr[roleClient] = append(list, role)
			return
		}
	}
	appendTo(d, "users", map[string]any{
		"username": user, "enabled": true, "serviceAccountClientId": owner,
		"clientRoles": map[string]any{roleClient: []any{role}},
	})
	b.addresses[name+"\x00"+fmt.Sprintf("service account of client %q", owner)] = r.Address
}

// clientIDOf finds the clientId of the client an attribute references.
func (b *builder) clientIDOf(r res, attr string) string {
	for _, ref := range b.refs[r.Address][attr] {
		addr := ref
		for _, suffix := range []string{".id", ".service_account_user_id"} {
			addr = strings.TrimSuffix(addr, suffix)
		}
		if t, ok := b.byAddr[addr]; ok && t.Type == "keycloak_openid_client" {
			if id, ok := t.Values["client_id"].(string); ok {
				return id
			}
		}
	}
	return ""
}

func (b *builder) addUser(r res) {
	name, ok := b.realmOf(r, "realm_id")
	if !ok {
		return
	}
	username, _ := r.Values["username"].(string)
	if username == "" {
		return
	}
	u := map[string]any{"username": username, "enabled": true}
	copyBool(r.Values, "enabled", u, "enabled")
	copyString(r.Values, "email", u, "email")
	u["requiredActions"] = stringList(r.Values["required_actions"])
	appendTo(b.realms[name], "users", u)
	b.addresses[name+"\x00"+fmt.Sprintf("user %q", username)] = r.Address
}

func appendTo(d map[string]any, key string, v any) {
	list, _ := d[key].([]any)
	d[key] = append(list, v)
}

func copyBool(from map[string]any, k string, to map[string]any, tk string) {
	if v, ok := from[k].(bool); ok {
		to[tk] = v
	}
}

func copyString(from map[string]any, k string, to map[string]any, tk string) {
	if v, ok := from[k].(string); ok && v != "" {
		to[tk] = v
	}
}

func copySeconds(from map[string]any, k string, to map[string]any, tk string) {
	if s, ok := seconds(from[k]); ok {
		to[tk] = s
	}
}

// seconds reads the provider's durations ("5m", "1h0m0s") or numbers.
func seconds(v any) (int, bool) {
	switch x := v.(type) {
	case string:
		if x == "" {
			return 0, false
		}
		d, err := time.ParseDuration(x)
		if err != nil {
			return 0, false
		}
		return int(d.Seconds()), true
	case float64:
		return int(x), true
	}
	return 0, false
}

func stringList(v any) []any {
	list, _ := v.([]any)
	if list == nil {
		return []any{}
	}
	return list
}

func firstBlock(v any) map[string]any {
	list, _ := v.([]any)
	if len(list) == 0 {
		return nil
	}
	m, _ := list[0].(map[string]any)
	return m
}

// NewFindings returns the findings in after that are not already in before,
// so CI can fail on what a plan introduces rather than on existing debt.
func NewFindings(after, before []check.Finding) []check.Finding {
	key := func(f check.Finding) string {
		return f.CheckID + "\x1f" + f.Realm + "\x1f" + f.Object + "\x1f" + f.Message
	}
	old := map[string]bool{}
	for _, f := range before {
		old[key(f)] = true
	}
	var out []check.Finding
	for _, f := range after {
		if !old[key(f)] {
			out = append(out, f)
		}
	}
	return out
}
