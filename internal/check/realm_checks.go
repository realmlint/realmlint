package check

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Password length thresholds. NIST SP 800-63B-4 sets 8 characters as the
// minimum when a password is one of several factors, and 15 when it is the
// only factor.
const (
	minPasswordLength         = 8
	recommendedPasswordLength = 15
)

var passwordLengthRule = regexp.MustCompile(`(?:^|\s)length\((\d+)\)`)

var realmChecks = []Check{
	{
		ID:      "ssl-required-none",
		Setting: "sslRequired",
		Title:   "HTTPS is not required",
		Why:     "With Require SSL set to none, Keycloak accepts logins and issues tokens over plain HTTP from any address, so passwords and tokens can be read on the network.",
		Fix:     `In Realm settings > General, set Require SSL to "external requests" or "all requests".`,
		Run: func(ctx *Context) []Finding {
			if ctx.Realm.SSLRequired != "none" {
				return nil
			}
			return []Finding{{Severity: High, Message: `sslRequired is "none"`}}
		},
	},
	{
		ID:      "brute-force-disabled",
		Setting: "bruteForceProtected",
		Title:   "Brute-force protection is off",
		Why:     "Without brute-force detection, attackers can try unlimited passwords against any account.",
		Fix:     "In Realm settings > Security defenses > Brute force detection, enable lockout.",
		Run: func(ctx *Context) []Finding {
			if ctx.Realm.BruteForceProtected {
				return nil
			}
			return []Finding{{Severity: Medium, Message: "brute-force detection is disabled"}}
		},
	},
	{
		ID:      "weak-password-policy",
		Setting: "passwordPolicy",
		Title:   "Password policy is weak",
		Why:     "Short or unrestricted passwords are easy to guess or crack, especially for accounts without a second factor.",
		Fix:     fmt.Sprintf("In Authentication > Policies > Password policy, add a minimum length of at least %d characters (%d if users have no second factor).", minPasswordLength, recommendedPasswordLength),
		Run: func(ctx *Context) []Finding {
			policy := strings.TrimSpace(ctx.Realm.PasswordPolicy)
			if policy == "" {
				return []Finding{{Severity: Medium, Message: "no password policy is set"}}
			}
			m := passwordLengthRule.FindStringSubmatch(policy)
			if m == nil {
				return []Finding{{Severity: Medium, Message: fmt.Sprintf("password policy %q has no minimum length", policy)}}
			}
			n, _ := strconv.Atoi(m[1])
			switch {
			case n < minPasswordLength:
				return []Finding{{Severity: Medium, Message: fmt.Sprintf("minimum password length is %d", n)}}
			case n < recommendedPasswordLength:
				return []Finding{{Severity: Low, Message: fmt.Sprintf("minimum password length is %d; %d is recommended for passwords used without a second factor", n, recommendedPasswordLength)}}
			}
			return nil
		},
	},
	{
		ID:      "login-events-disabled",
		Setting: "eventsEnabled",
		Title:   "Login events are not saved",
		Why:     "Without saved login events there is no record of failed logins, lockouts or token use to investigate an incident.",
		Fix:     "In Realm settings > Events > User events settings, turn on Save events and set an expiration.",
		Run: func(ctx *Context) []Finding {
			if ctx.Realm.EventsEnabled {
				return nil
			}
			return []Finding{{Severity: Low, Message: "user events are not saved"}}
		},
	},
	{
		ID:      "admin-events-disabled",
		Setting: "adminEventsEnabled",
		Title:   "Admin events are not saved",
		Why:     "Admin events are the only record of who changed the realm's configuration. Without them, changes cannot be traced to a person.",
		Fix:     "In Realm settings > Events > Admin events settings, turn on Save events and Include representation.",
		Run: func(ctx *Context) []Finding {
			switch {
			case !ctx.Realm.AdminEventsEnabled:
				return []Finding{{Severity: Medium, Message: "admin events are not saved"}}
			case !ctx.Realm.AdminEventsDetailsEnabled:
				return []Finding{{Severity: Low, Message: "admin events are saved without the changed representation, so they show who changed something but not what"}}
			}
			return nil
		},
	},
	{
		ID:    "master-realm-in-use",
		Title: "Applications use the master realm",
		Why:   "The master realm controls every other realm. Application clients there widen the attack surface of Keycloak's administration.",
		Fix:   "Move application clients to their own realm and keep master for Keycloak administrators only.",
		Run: func(ctx *Context) []Finding {
			if ctx.Realm.Realm != "master" {
				return nil
			}
			var findings []Finding
			for i := range ctx.Realm.Clients {
				c := &ctx.Realm.Clients[i]
				if isBuiltinClient("master", c.ClientID) {
					continue
				}
				findings = append(findings, Finding{
					Severity: Medium,
					Object:   clientObject(c),
					Message:  "application client defined in the master realm",
				})
			}
			return findings
		},
	},
}
