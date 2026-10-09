package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/realmlint/realmlint/pkg/redact"
)

// Realms returns the names of the realms the agent's client can see.
func (c *Client) Realms(ctx context.Context) ([]string, error) {
	var realms []map[string]any
	if err := c.get(ctx, "/realms?briefRepresentation=true", &realms); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(realms))
	for _, r := range realms {
		if name, _ := r["realm"].(string); name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

// Version returns the Keycloak version, or "" when the server does not
// reveal it to this client (it only does for master-realm administrators).
func (c *Client) Version(ctx context.Context) string {
	var info struct {
		SystemInfo struct {
			Version string `json:"version"`
		} `json:"systemInfo"`
	}
	if err := c.get(ctx, "/serverinfo", &info); err != nil {
		return ""
	}
	return info.SystemInfo.Version
}

// Snapshot reads one realm and returns it in the shape of `kc.sh export`
// (realm settings, clients, roles, groups, users, identity providers and
// components), with secrets masked. version, if not empty, is recorded as
// keycloakVersion.
func (c *Client) Snapshot(ctx context.Context, realmName, version string) (map[string]any, error) {
	r := "/realms/" + url.PathEscape(realmName)

	var realm map[string]any
	if err := c.get(ctx, r, &realm); err != nil {
		return nil, err
	}
	if version != "" {
		realm["keycloakVersion"] = version
	}

	clients, err := c.getList(ctx, r+"/clients")
	if err != nil {
		return nil, err
	}
	realm["clients"] = toAny(clients)
	clientIDByUUID := map[string]string{}
	for _, cl := range clients {
		clientIDByUUID[str(cl["id"])] = str(cl["clientId"])
	}

	roles, err := c.roles(ctx, r, clients, clientIDByUUID)
	if err != nil {
		return nil, err
	}
	realm["roles"] = roles

	groups, err := c.groups(ctx, r, r+"/groups?briefRepresentation=false")
	if err != nil {
		return nil, err
	}
	realm["groups"] = groups

	users, err := c.users(ctx, r, clients)
	if err != nil {
		return nil, err
	}
	realm["users"] = users

	var idps []map[string]any
	if err := c.get(ctx, r+"/identity-provider/instances", &idps); err != nil {
		return nil, err
	}
	realm["identityProviders"] = toAny(idps)

	components, err := c.components(ctx, r)
	if err != nil {
		return nil, err
	}
	realm["components"] = components

	redact.Value(realm)
	if leaks := redact.Leaks(realm); len(leaks) > 0 {
		return nil, fmt.Errorf("realm %s: secrets still present after masking at %s; snapshot not written", realmName, strings.Join(leaks, ", "))
	}
	return realm, nil
}

// roles returns {"realm": [...], "client": {clientId: [...]}}, with each
// composite role's composites listed by name as in an export.
func (c *Client) roles(ctx context.Context, r string, clients []map[string]any, clientIDByUUID map[string]string) (map[string]any, error) {
	realmRoles, err := c.getList(ctx, r+"/roles?briefRepresentation=false")
	if err != nil {
		return nil, err
	}
	if err := c.addComposites(ctx, r, realmRoles, clientIDByUUID); err != nil {
		return nil, err
	}
	clientRoles := map[string]any{}
	for _, cl := range clients {
		list, err := c.getList(ctx, r+"/clients/"+url.PathEscape(str(cl["id"]))+"/roles?briefRepresentation=false")
		if err != nil {
			return nil, err
		}
		if err := c.addComposites(ctx, r, list, clientIDByUUID); err != nil {
			return nil, err
		}
		clientRoles[str(cl["clientId"])] = toAny(list)
	}
	return map[string]any{"realm": toAny(realmRoles), "client": clientRoles}, nil
}

func (c *Client) addComposites(ctx context.Context, r string, roles []map[string]any, clientIDByUUID map[string]string) error {
	for _, role := range roles {
		if composite, _ := role["composite"].(bool); !composite {
			continue
		}
		parts, err := c.getList(ctx, r+"/roles-by-id/"+url.PathEscape(str(role["id"]))+"/composites")
		if err != nil {
			return err
		}
		realmNames := []any{}
		clientNames := map[string]any{}
		for _, p := range parts {
			if isClient, _ := p["clientRole"].(bool); isClient {
				id := clientIDByUUID[str(p["containerId"])]
				list, _ := clientNames[id].([]any)
				clientNames[id] = append(list, str(p["name"]))
				continue
			}
			realmNames = append(realmNames, str(p["name"]))
		}
		comp := map[string]any{}
		if len(realmNames) > 0 {
			comp["realm"] = realmNames
		}
		if len(clientNames) > 0 {
			comp["client"] = clientNames
		}
		role["composites"] = comp
	}
	return nil
}

// groups returns the groups at path with their subgroups filled in.
func (c *Client) groups(ctx context.Context, r, path string) ([]any, error) {
	list, err := c.getList(ctx, path)
	if err != nil {
		return nil, err
	}
	for _, g := range list {
		if n, _ := g["subGroupCount"].(interface{ Int64() (int64, error) }); n != nil {
			if count, _ := n.Int64(); count == 0 {
				g["subGroups"] = []any{}
				continue
			}
		}
		children, err := c.groups(ctx, r, r+"/groups/"+url.PathEscape(str(g["id"]))+"/children?briefRepresentation=false")
		if err != nil {
			return nil, err
		}
		g["subGroups"] = children
	}
	return toAny(list), nil
}

// users returns every user plus the service account user of each client
// that has one, with role mappings, group paths and credential types.
func (c *Client) users(ctx context.Context, r string, clients []map[string]any) ([]any, error) {
	list, err := c.getList(ctx, r+"/users?briefRepresentation=false")
	if err != nil {
		return nil, err
	}
	for _, cl := range clients {
		if enabled, _ := cl["serviceAccountsEnabled"].(bool); !enabled {
			continue
		}
		var sa map[string]any
		if err := c.get(ctx, r+"/clients/"+url.PathEscape(str(cl["id"]))+"/service-account-user", &sa); err != nil {
			return nil, err
		}
		sa["serviceAccountClientId"] = str(cl["clientId"])
		list = append(list, sa)
	}

	for _, u := range list {
		base := r + "/users/" + url.PathEscape(str(u["id"]))

		var mappings struct {
			RealmMappings  []map[string]any `json:"realmMappings"`
			ClientMappings map[string]struct {
				Mappings []map[string]any `json:"mappings"`
			} `json:"clientMappings"`
		}
		if err := c.get(ctx, base+"/role-mappings", &mappings); err != nil {
			return nil, err
		}
		realmRoles := []any{}
		for _, m := range mappings.RealmMappings {
			realmRoles = append(realmRoles, str(m["name"]))
		}
		clientRoles := map[string]any{}
		for clientID, cm := range mappings.ClientMappings {
			names := []any{}
			for _, m := range cm.Mappings {
				names = append(names, str(m["name"]))
			}
			clientRoles[clientID] = names
		}
		u["realmRoles"] = realmRoles
		u["clientRoles"] = clientRoles

		groups, err := c.getList(ctx, base+"/groups")
		if err != nil {
			return nil, err
		}
		paths := []any{}
		for _, g := range groups {
			paths = append(paths, str(g["path"]))
		}
		u["groups"] = paths

		var creds []map[string]any
		if err := c.get(ctx, base+"/credentials", &creds); err != nil {
			return nil, err
		}
		// Keep only what the checks need; never hashes or salts.
		kept := []any{}
		for _, cr := range creds {
			kept = append(kept, map[string]any{"id": cr["id"], "type": cr["type"], "createdDate": cr["createdDate"]})
		}
		u["credentials"] = kept
	}
	return toAny(list), nil
}

// components returns the realm's components grouped by provider type, as in
// an export. Key providers get their certificate and active state from
// /keys, because /components leaves certificates out; private keys are never
// requested.
func (c *Client) components(ctx context.Context, r string) (map[string]any, error) {
	var all []map[string]any
	if err := c.get(ctx, r+"/components", &all); err != nil {
		return nil, err
	}
	var keys struct {
		Keys []struct {
			ProviderID  string `json:"providerId"`
			Status      string `json:"status"`
			Certificate string `json:"certificate"`
		} `json:"keys"`
	}
	if err := c.get(ctx, r+"/keys", &keys); err != nil {
		return nil, err
	}
	certs := map[string]string{}
	status := map[string]string{}
	for _, k := range keys.Keys {
		if k.Certificate != "" {
			certs[k.ProviderID] = k.Certificate
		}
		status[k.ProviderID] = k.Status
	}

	byType := map[string]any{}
	for _, comp := range all {
		providerType := str(comp["providerType"])
		if providerType == "" {
			continue
		}
		if providerType == "org.keycloak.keys.KeyProvider" {
			config, _ := comp["config"].(map[string]any)
			if config == nil {
				config = map[string]any{}
				comp["config"] = config
			}
			id := str(comp["id"])
			if cert := certs[id]; cert != "" {
				config["certificate"] = []any{cert}
			}
			switch status[id] {
			case "PASSIVE":
				config["active"] = []any{"false"}
			case "DISABLED":
				config["enabled"] = []any{"false"}
			}
		}
		list, _ := byType[providerType].([]any)
		byType[providerType] = append(list, comp)
	}
	return byType, nil
}

// AdminEvents returns the realm's admin events at or after since, oldest
// first. Admin events must be enabled in the realm for there to be any.
func (c *Client) AdminEvents(ctx context.Context, realmName string, since time.Time) ([]any, error) {
	path := "/realms/" + url.PathEscape(realmName) + "/admin-events?dateFrom=" + since.UTC().Format("2006-01-02")
	events, err := c.getList(ctx, path)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == 404 {
			return nil, nil
		}
		return nil, err
	}
	sinceMs := since.UnixMilli()
	out := []any{}
	// Keycloak returns the newest first.
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		t, _ := strconv.ParseInt(str(e["time"]), 10, 64)
		if t < sinceMs {
			continue
		}
		maskRepresentation(e)
		redact.Value(e)
		if leaks := redact.Leaks(e); len(leaks) > 0 {
			return nil, fmt.Errorf("realm %s: admin event still contains secrets at %s; events not written", realmName, strings.Join(leaks, ", "))
		}
		out = append(out, e)
	}
	return out, nil
}

// maskRepresentation masks secrets inside an admin event's representation,
// which Keycloak stores as a JSON document in a string. A representation that
// is not valid JSON is dropped, because it cannot be checked.
func maskRepresentation(e map[string]any) {
	rep, ok := e["representation"].(string)
	if !ok || rep == "" {
		return
	}
	var doc any
	if err := json.Unmarshal([]byte(rep), &doc); err != nil {
		delete(e, "representation")
		e["representationDropped"] = true
		return
	}
	redact.Value(doc)
	masked, err := json.Marshal(doc)
	if err != nil || len(redact.Leaks(doc)) > 0 {
		delete(e, "representation")
		e["representationDropped"] = true
		return
	}
	e["representation"] = string(masked)
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func toAny(list []map[string]any) []any {
	out := make([]any, len(list))
	for i, m := range list {
		out[i] = m
	}
	return out
}
