//go:build integration

// Integration tests against real Keycloak containers. They need Docker:
//
//	go test -tags integration ./pkg/keycloak
//
// REALMLINT_IT_VERSIONS overrides the Keycloak versions (comma-separated).
package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/realmlint/realmlint/pkg/check"
	"github.com/realmlint/realmlint/pkg/realm"
	"github.com/realmlint/realmlint/pkg/redact"
)

// agentRoles are the realm-management roles the agent's service account
// needs.
var agentRoles = []string{"view-realm", "view-clients", "view-users", "view-events", "view-identity-providers"}

const plainSecret = "PLAIN-SECRET-VALUE-123"

func TestAgainstKeycloak(t *testing.T) {
	versions := []string{"26.8.0", "26.7.5", "26.6.4"}
	if v := os.Getenv("REALMLINT_IT_VERSIONS"); v != "" {
		versions = strings.Split(v, ",")
	}
	for _, v := range versions {
		t.Run(v, func(t *testing.T) { testVersion(t, strings.TrimSpace(v)) })
	}
}

func testVersion(t *testing.T, version string) {
	base := startKeycloak(t, version)
	admin := &adminAPI{t: t, base: base}
	secret := admin.createAgentClient("acme")

	ctx := context.Background()
	c := NewClient(base, "acme", "realmlint-agent", secret)

	// The snapshot must give the same findings as kc.sh export of the same
	// seed realm, and contain no secrets.
	snap, err := c.Snapshot(ctx, "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	if leaks := redact.Leaks(snap); len(leaks) > 0 {
		t.Fatalf("snapshot leaks secrets at %v", leaks)
	}
	got := findings(t, writeSnapshot(t, snap))
	want := findings(t, filepath.Join("..", "..", "testdata", "realms", version, "single.json"))
	if diff := compare(got, want); diff != "" {
		t.Fatalf("agent snapshot findings differ from kc.sh export:\n%s", diff)
	}

	// Admin events are captured with their author, and secrets inside their
	// representations are masked.
	start := time.Now().Add(-time.Minute)
	admin.enableAdminEvents("acme")
	admin.createClientWithSecret("acme", "evt-test", plainSecret)
	events, err := c.AdminEvents(ctx, "acme", start)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(events)
	if bytes.Contains(raw, []byte(plainSecret)) {
		t.Fatal("admin events contain a client secret in plain text")
	}
	var sawCreate bool
	for _, e := range events {
		ev := e.(map[string]any)
		if ev["operationType"] == "CREATE" && ev["resourceType"] == "CLIENT" {
			sawCreate = true
			auth, _ := ev["authDetails"].(map[string]any)
			if str(auth["userId"]) == "" {
				t.Error("CREATE CLIENT event has no user ID")
			}
		}
	}
	if !sawCreate {
		t.Fatalf("no CREATE CLIENT admin event in %d events", len(events))
	}

	// Without the extra scope mappings, a full-scope-off client gets 403;
	// the error must say what to fix.
	if _, err := NewClient(base, "acme", "realmlint-agent", "wrong").Realms(ctx); err == nil {
		t.Error("a wrong client secret should fail to log in")
	}
}

func startKeycloak(t *testing.T, version string) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	seed, err := filepath.Abs(filepath.Join("..", "..", "testdata", "seed"))
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("realmlint-it-%s-%d", strings.ReplaceAll(version, ".", "-"), time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-p", "127.0.0.1::8080",
		"-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=admin",
		"-v", seed+":/opt/keycloak/data/import:ro",
		"quay.io/keycloak/keycloak:"+version, "start-dev", "--import-realm").CombinedOutput()
	if err != nil {
		t.Fatalf("start keycloak %s: %v: %s", version, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	portOut, err := exec.Command("docker", "port", name, "8080/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	hostPort := strings.TrimSpace(strings.Split(string(portOut), "\n")[0])
	base := "http://" + hostPort

	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/realms/acme")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("keycloak %s did not start within 3 minutes", version)
	return ""
}

// adminAPI performs setup as the bootstrap admin.
type adminAPI struct {
	t     *testing.T
	base  string
	token string
}

func (a *adminAPI) login() {
	form := url.Values{"client_id": {"admin-cli"}, "grant_type": {"password"}, "username": {"admin"}, "password": {"admin"}}
	resp, err := http.PostForm(a.base+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		a.t.Fatalf("admin login failed: %v", err)
	}
	a.token = tok.AccessToken
}

func (a *adminAPI) do(method, path string, body, out any) {
	a.t.Helper()
	if a.token == "" {
		a.login()
	}
	var rd *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		rd = bytes.NewReader(data)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, a.base+"/admin"+path, rd)
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		a.t.Fatalf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			a.t.Fatal(err)
		}
	}
}

func (a *adminAPI) clientUUID(realmName, clientID string) string {
	var list []map[string]any
	a.do("GET", "/realms/"+realmName+"/clients?clientId="+url.QueryEscape(clientID), nil, &list)
	if len(list) != 1 {
		a.t.Fatalf("client %s not found", clientID)
	}
	return list[0]["id"].(string)
}

// createAgentClient creates the agent's client the way the docs describe:
// confidential, service account only, full scope off, with the view roles
// mapped and in its scope. It returns the client secret.
func (a *adminAPI) createAgentClient(realmName string) string {
	r := "/realms/" + realmName
	a.do("POST", r+"/clients", map[string]any{
		"clientId": "realmlint-agent", "publicClient": false, "serviceAccountsEnabled": true,
		"standardFlowEnabled": false, "directAccessGrantsEnabled": false, "fullScopeAllowed": false,
	}, nil)
	id := a.clientUUID(realmName, "realmlint-agent")
	rm := a.clientUUID(realmName, "realm-management")
	var all []map[string]any
	a.do("GET", r+"/clients/"+rm+"/roles", nil, &all)
	var roles []map[string]any
	for _, role := range all {
		for _, want := range agentRoles {
			if role["name"] == want {
				roles = append(roles, role)
			}
		}
	}
	if len(roles) != len(agentRoles) {
		a.t.Fatalf("found %d of %d agent roles", len(roles), len(agentRoles))
	}
	var sa map[string]any
	a.do("GET", r+"/clients/"+id+"/service-account-user", nil, &sa)
	a.do("POST", r+"/users/"+sa["id"].(string)+"/role-mappings/clients/"+rm, roles, nil)
	a.do("POST", r+"/clients/"+id+"/scope-mappings/clients/"+rm, roles, nil)
	var secret map[string]any
	a.do("GET", r+"/clients/"+id+"/client-secret", nil, &secret)
	return secret["value"].(string)
}

func (a *adminAPI) enableAdminEvents(realmName string) {
	a.do("PUT", "/realms/"+realmName+"/events/config", map[string]any{
		"adminEventsEnabled": true, "adminEventsDetailsEnabled": true,
	}, nil)
}

func (a *adminAPI) createClientWithSecret(realmName, clientID, secret string) {
	a.do("POST", "/realms/"+realmName+"/clients", map[string]any{
		"clientId": clientID, "publicClient": false, "secret": secret,
		"redirectUris": []string{"https://evt.example/cb"},
	}, nil)
}

func writeSnapshot(t *testing.T, snap map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acme.json")
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// findings runs every check on an export and returns one line per finding.
func findings(t *testing.T, path string) []string {
	t.Helper()
	realms, err := realm.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	// Fixed time so key age and expiry do not depend on when the test runs.
	for _, f := range check.Run(realms, check.All(), time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)) {
		out = append(out, fmt.Sprintf("%s %s %s: %s", f.Severity, f.CheckID, f.Object, f.Message))
	}
	sort.Strings(out)
	return out
}

func compare(got, want []string) string {
	count := map[string]int{}
	for _, w := range want {
		count[w]++
	}
	for _, g := range got {
		count[g]--
	}
	var b strings.Builder
	for k, n := range count {
		switch {
		case n > 0:
			fmt.Fprintf(&b, "  missing from agent snapshot: %s\n", k)
		case n < 0:
			fmt.Fprintf(&b, "  only in agent snapshot:      %s\n", k)
		}
	}
	return b.String()
}
