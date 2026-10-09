// Package realm reads Keycloak realm exports into a typed model.
//
// The model covers the parts of Keycloak's RealmRepresentation that
// realmlint checks. Unknown fields are ignored, so exports from newer
// Keycloak releases still load. Fields whose Keycloak default is true are
// pointers, and the accessor methods apply that default when the export
// leaves them out.
package realm

// Component provider types used in Realm.Components.
const (
	KeyProviderType         = "org.keycloak.keys.KeyProvider"
	UserStorageProviderType = "org.keycloak.storage.UserStorageProvider"
)

// Realm is one Keycloak realm.
type Realm struct {
	Realm           string `json:"realm"`
	ID              string `json:"id"`
	Enabled         bool   `json:"enabled"`
	KeycloakVersion string `json:"keycloakVersion"`

	SSLRequired         string `json:"sslRequired"`
	BruteForceProtected bool   `json:"bruteForceProtected"`
	PermanentLockout    bool   `json:"permanentLockout"`
	FailureFactor       int    `json:"failureFactor"`
	PasswordPolicy      string `json:"passwordPolicy"`
	RegistrationAllowed bool   `json:"registrationAllowed"`
	VerifyEmail         bool   `json:"verifyEmail"`

	EventsEnabled             bool     `json:"eventsEnabled"`
	EventsExpiration          int64    `json:"eventsExpiration"`
	EventsListeners           []string `json:"eventsListeners"`
	AdminEventsEnabled        bool     `json:"adminEventsEnabled"`
	AdminEventsDetailsEnabled bool     `json:"adminEventsDetailsEnabled"`

	// Token and session lifetimes, in seconds.
	AccessTokenLifespan                int  `json:"accessTokenLifespan"`
	AccessTokenLifespanForImplicitFlow int  `json:"accessTokenLifespanForImplicitFlow"`
	SSOSessionIdleTimeout              int  `json:"ssoSessionIdleTimeout"`
	SSOSessionMaxLifespan              int  `json:"ssoSessionMaxLifespan"`
	ClientSessionIdleTimeout           int  `json:"clientSessionIdleTimeout"`
	ClientSessionMaxLifespan           int  `json:"clientSessionMaxLifespan"`
	OfflineSessionIdleTimeout          int  `json:"offlineSessionIdleTimeout"`
	OfflineSessionMaxLifespanEnabled   bool `json:"offlineSessionMaxLifespanEnabled"`
	OfflineSessionMaxLifespan          int  `json:"offlineSessionMaxLifespan"`
	RevokeRefreshToken                 bool `json:"revokeRefreshToken"`
	RefreshTokenMaxReuse               int  `json:"refreshTokenMaxReuse"`

	Attributes        Attributes             `json:"attributes"`
	Roles             Roles                  `json:"roles"`
	Groups            []Group                `json:"groups"`
	Clients           []Client               `json:"clients"`
	Users             []User                 `json:"users"`
	IdentityProviders []IdentityProvider     `json:"identityProviders"`
	Components        map[string][]Component `json:"components"`

	// Source is the file the realm was loaded from.
	Source string `json:"-"`
	// Raw is the complete export as generic JSON (numbers as json.Number),
	// including fields the model does not cover. Users from separate users
	// files are merged into Raw["users"].
	Raw map[string]any `json:"-"`
}

// ComponentsOf returns the realm's components of one provider type, such as
// KeyProviderType.
func (r *Realm) ComponentsOf(providerType string) []Component {
	return r.Components[providerType]
}

// Client is a Keycloak client.
type Client struct {
	ID                        string     `json:"id"`
	ClientID                  string     `json:"clientId"`
	Name                      string     `json:"name"`
	Enabled                   *bool      `json:"enabled"`
	Protocol                  string     `json:"protocol"`
	PublicClient              bool       `json:"publicClient"`
	BearerOnly                bool       `json:"bearerOnly"`
	ClientAuthenticatorType   string     `json:"clientAuthenticatorType"`
	StandardFlowEnabled       *bool      `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool       `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool       `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool       `json:"serviceAccountsEnabled"`
	FullScopeAllowed          *bool      `json:"fullScopeAllowed"`
	RootURL                   string     `json:"rootUrl"`
	BaseURL                   string     `json:"baseUrl"`
	RedirectURIs              []string   `json:"redirectUris"`
	WebOrigins                []string   `json:"webOrigins"`
	DefaultClientScopes       []string   `json:"defaultClientScopes"`
	OptionalClientScopes      []string   `json:"optionalClientScopes"`
	Attributes                Attributes `json:"attributes"`
}

// IsEnabled reports whether the client is enabled. Keycloak's default is true.
func (c *Client) IsEnabled() bool { return boolOr(c.Enabled, true) }

// UsesStandardFlow reports whether the authorization code flow is enabled.
// Keycloak's default is true.
func (c *Client) UsesStandardFlow() bool { return boolOr(c.StandardFlowEnabled, true) }

// HasFullScope reports whether tokens for the client carry all of the user's
// roles. Keycloak's default is true.
func (c *Client) HasFullScope() bool { return boolOr(c.FullScopeAllowed, true) }

// Roles holds realm roles and client roles keyed by client ID.
type Roles struct {
	Realm  []Role            `json:"realm"`
	Client map[string][]Role `json:"client"`
}

// Role is a realm or client role.
type Role struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Composite   bool        `json:"composite"`
	Composites  *Composites `json:"composites"`
	ClientRole  bool        `json:"clientRole"`
	ContainerID string      `json:"containerId"`
}

// Composites lists the roles a composite role includes.
type Composites struct {
	Realm  []string            `json:"realm"`
	Client map[string][]string `json:"client"`
}

// Group is a group and its subgroups.
type Group struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Path        string              `json:"path"`
	RealmRoles  []string            `json:"realmRoles"`
	ClientRoles map[string][]string `json:"clientRoles"`
	SubGroups   []Group             `json:"subGroups"`
}

// User is a user or a client's service account.
type User struct {
	ID                     string              `json:"id"`
	Username               string              `json:"username"`
	Enabled                bool                `json:"enabled"`
	Email                  string              `json:"email"`
	CreatedTimestamp       int64               `json:"createdTimestamp"`
	FederationLink         string              `json:"federationLink"`
	ServiceAccountClientID string              `json:"serviceAccountClientId"`
	RealmRoles             []string            `json:"realmRoles"`
	ClientRoles            map[string][]string `json:"clientRoles"`
	Groups                 []string            `json:"groups"`
	RequiredActions        []string            `json:"requiredActions"`
	Credentials            []Credential        `json:"credentials"`
	Attributes             MultiValue          `json:"attributes"`
}

// IsServiceAccount reports whether the user is a client's service account.
func (u *User) IsServiceAccount() bool { return u.ServiceAccountClientID != "" }

// Credential describes a user credential. Secret values are not modelled.
type Credential struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	CreatedDate int64  `json:"createdDate"`
}

// IdentityProvider is an external identity provider (OIDC, SAML, social).
type IdentityProvider struct {
	Alias       string     `json:"alias"`
	InternalID  string     `json:"internalId"`
	ProviderID  string     `json:"providerId"`
	DisplayName string     `json:"displayName"`
	Enabled     bool       `json:"enabled"`
	Config      Attributes `json:"config"`
}

// Component is a configured provider, such as a realm key or an LDAP
// connection.
type Component struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	ProviderID    string                 `json:"providerId"`
	SubType       string                 `json:"subType"`
	Config        MultiValue             `json:"config"`
	SubComponents map[string][]Component `json:"subComponents"`
}

func boolOr(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}
