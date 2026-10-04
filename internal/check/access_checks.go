package check

import (
	"strings"

	"github.com/edzordzinam/realmlint/internal/realm"
)

// Credential types and required actions that count as a second factor.
var (
	mfaCredentialTypes = map[string]bool{
		"otp":                   true,
		"webauthn":              true,
		"webauthn-passwordless": true,
	}
	mfaRequiredActions = map[string]bool{
		"CONFIGURE_TOTP":                 true,
		"webauthn-register":              true,
		"webauthn-register-passwordless": true,
	}
)

var accessChecks = []Check{
	{
		ID:    "service-account-admin",
		Title: "Service account has realm admin rights",
		Why:   "A client's service account with realm-admin can change any setting, user or client in the realm. Anyone with the client secret has full control.",
		Fix:   "Remove realm-admin from the service account and grant only the specific realm-management roles it needs, such as view-users or manage-users.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for _, u := range admins(ctx.Realm) {
				if u.IsServiceAccount() {
					findings = append(findings, Finding{Severity: High, Object: userObject(u), Message: "service account has full realm admin rights"})
				}
			}
			return findings
		},
	},
	{
		ID:    "admin-without-mfa",
		Title: "Admin account has no second factor",
		Why:   "Realm admins can change everything in the realm. Without a second factor, one leaked or guessed password is enough to take over.",
		Fix:   "Require OTP or WebAuthn for administrators: add Configure OTP as a required action for the user, or enforce a second factor in the login flow. Ignore this finding if admins log in through an identity provider that enforces MFA.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for _, u := range admins(ctx.Realm) {
				if u.IsServiceAccount() || !u.Enabled || hasMFA(u) {
					continue
				}
				findings = append(findings, Finding{Severity: High, Object: userObject(u), Message: "admin user has no OTP or WebAuthn credential"})
			}
			return findings
		},
	},
	{
		ID:    "temporary-admin-present",
		Title: "Temporary bootstrap admin still exists",
		Why:   "Keycloak creates a temporary admin on first start so you can set up a permanent one. Left in place, it is a well-known account with full control of every realm.",
		Fix:   "Create a permanent admin account with a second factor, then delete the temporary admin.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for i := range ctx.Realm.Users {
				u := &ctx.Realm.Users[i]
				if u.Attributes.First("is_temporary_admin") == "true" {
					findings = append(findings, Finding{Severity: High, Object: userObject(u), Message: "temporary bootstrap admin account is still present"})
				}
			}
			return findings
		},
	},
}

func hasMFA(u *realm.User) bool {
	for _, c := range u.Credentials {
		if mfaCredentialTypes[c.Type] {
			return true
		}
	}
	for _, a := range u.RequiredActions {
		if mfaRequiredActions[a] {
			return true
		}
	}
	return false
}

// admins returns users whose effective roles give full admin rights over
// the realm: realm-management/realm-admin, or the admin role in master.
func admins(r *realm.Realm) []*realm.User {
	idx := newRoleIndex(r)
	var out []*realm.User
	for i := range r.Users {
		u := &r.Users[i]
		roles := idx.effectiveRoles(u)
		if roles[roleRef{client: "realm-management", name: "realm-admin"}] ||
			(r.Realm == "master" && roles[roleRef{name: "admin"}]) {
			out = append(out, u)
		}
	}
	return out
}

// roleRef identifies a realm role (client empty) or a client role.
type roleRef struct {
	client string
	name   string
}

type roleIndex struct {
	roles  map[roleRef]*realm.Role
	groups map[string]*realm.Group
}

func newRoleIndex(r *realm.Realm) *roleIndex {
	idx := &roleIndex{roles: map[roleRef]*realm.Role{}, groups: map[string]*realm.Group{}}
	for i := range r.Roles.Realm {
		role := &r.Roles.Realm[i]
		idx.roles[roleRef{name: role.Name}] = role
	}
	for client, roles := range r.Roles.Client {
		for i := range roles {
			idx.roles[roleRef{client: client, name: roles[i].Name}] = &roles[i]
		}
	}
	idx.addGroups(r.Groups, "")
	return idx
}

func (idx *roleIndex) addGroups(groups []realm.Group, parent string) {
	for i := range groups {
		g := &groups[i]
		path := g.Path
		if path == "" {
			path = parent + "/" + g.Name
		}
		idx.groups[path] = g
		idx.addGroups(g.SubGroups, path)
	}
}

// effectiveRoles returns the user's direct roles, roles from their groups
// and parent groups, and everything those roles include as composites.
func (idx *roleIndex) effectiveRoles(u *realm.User) map[roleRef]bool {
	seen := map[roleRef]bool{}
	var queue []roleRef
	add := func(ref roleRef) {
		if !seen[ref] {
			seen[ref] = true
			queue = append(queue, ref)
		}
	}
	addMappings := func(realmRoles []string, clientRoles map[string][]string) {
		for _, n := range realmRoles {
			add(roleRef{name: n})
		}
		for client, names := range clientRoles {
			for _, n := range names {
				add(roleRef{client: client, name: n})
			}
		}
	}

	addMappings(u.RealmRoles, u.ClientRoles)
	for _, path := range u.Groups {
		for _, p := range groupAndAncestors(path) {
			if g, ok := idx.groups[p]; ok {
				addMappings(g.RealmRoles, g.ClientRoles)
			}
		}
	}

	for len(queue) > 0 {
		ref := queue[0]
		queue = queue[1:]
		role, ok := idx.roles[ref]
		if !ok || role.Composites == nil {
			continue
		}
		addMappings(role.Composites.Realm, role.Composites.Client)
	}
	return seen
}

// groupAndAncestors returns "/a", "/a/b", "/a/b/c" for "/a/b/c". Subgroups
// inherit their parents' role mappings.
func groupAndAncestors(path string) []string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	out := make([]string, 0, len(parts))
	for i := range parts {
		out = append(out, "/"+strings.Join(parts[:i+1], "/"))
	}
	return out
}
