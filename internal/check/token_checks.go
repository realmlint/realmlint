package check

import (
	"fmt"
	"strconv"
)

// Token and session thresholds, in seconds.
const (
	maxAccessTokenLifespan = 15 * 60
	maxSSOSessionIdle      = 12 * 3600
	maxSSOSessionLifespan  = 14 * 86400
	// Keycloak's default offline session idle timeout, used when the export
	// leaves it out.
	defaultOfflineSessionIdle = 30 * 86400
)

var tokenChecks = []Check{
	{
		ID:    "long-access-token",
		Title: "Access tokens live too long",
		Why:   "Access tokens cannot be revoked before they expire. A leaked token stays usable for its whole lifetime.",
		Fix:   fmt.Sprintf("Set Access Token Lifespan to %s or less in Realm settings > Tokens, and remove longer per-client overrides in the client's Advanced tab.", humanDuration(maxAccessTokenLifespan)),
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			if n := ctx.Realm.AccessTokenLifespan; n > maxAccessTokenLifespan {
				findings = append(findings, Finding{
					Severity: Medium,
					Message:  fmt.Sprintf("access token lifespan is %s", humanDuration(n)),
				})
			}
			for i := range ctx.Realm.Clients {
				c := &ctx.Realm.Clients[i]
				n, err := strconv.Atoi(c.Attributes["access.token.lifespan"])
				if err != nil || !c.IsEnabled() || n <= maxAccessTokenLifespan {
					continue
				}
				findings = append(findings, Finding{
					Severity: Medium,
					Object:   clientObject(c),
					Message:  fmt.Sprintf("client overrides the access token lifespan to %s", humanDuration(n)),
				})
			}
			return findings
		},
	},
	{
		ID:    "long-sso-session",
		Title: "Login sessions last too long",
		Why:   "Refresh tokens stay valid as long as the login session. Long sessions keep stolen refresh tokens and unattended browsers logged in.",
		Fix:   fmt.Sprintf("In Realm settings > Sessions, set SSO Session Idle to %s or less and SSO Session Max to %s or less.", humanDuration(maxSSOSessionIdle), humanDuration(maxSSOSessionLifespan)),
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			if n := ctx.Realm.SSOSessionIdleTimeout; n > maxSSOSessionIdle {
				findings = append(findings, Finding{Severity: Medium, Message: fmt.Sprintf("SSO session idle timeout is %s", humanDuration(n))})
			}
			if n := ctx.Realm.SSOSessionMaxLifespan; n > maxSSOSessionLifespan {
				findings = append(findings, Finding{Severity: Medium, Message: fmt.Sprintf("SSO session max lifespan is %s", humanDuration(n))})
			}
			return findings
		},
	},
	{
		ID:    "offline-sessions-unbounded",
		Title: "Offline sessions never expire",
		Why:   "Offline tokens with no maximum lifespan stay valid forever as long as they are used regularly, so a leaked offline token gives permanent access.",
		Fix:   "In Realm settings > Sessions, enable Offline Session Max Limited and set Offline Session Max.",
		Run: func(ctx *Context) []Finding {
			if ctx.Realm.OfflineSessionMaxLifespanEnabled {
				return nil
			}
			idle := ctx.Realm.OfflineSessionIdleTimeout
			if idle == 0 {
				idle = defaultOfflineSessionIdle
			}
			return []Finding{{
				Severity: Low,
				Message:  fmt.Sprintf("offline sessions have no maximum lifespan; they expire only after %s without use", humanDuration(idle)),
			}}
		},
	},
}
