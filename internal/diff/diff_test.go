package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/edzordzinam/realmlint/internal/check"
	"github.com/edzordzinam/realmlint/internal/realm"
)

func load(t *testing.T, content string) []*realm.Realm {
	t.Helper()
	path := filepath.Join(t.TempDir(), "export.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	realms, err := realm.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return realms
}

// change is the expected form of a Change: before and after as JSON text,
// "" when absent.
type change struct {
	kind          Kind
	path          string
	before, after string
	hidden        bool
}

func summarise(changes []Change) []change {
	out := make([]change, len(changes))
	for i, c := range changes {
		out[i] = change{kind: c.Kind, path: c.Path, before: jsonText(c.Before), after: jsonText(c.After), hidden: c.Hidden}
	}
	return out
}

func jsonText(v any) string {
	if v == nil {
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestCompare(t *testing.T) {
	tests := []struct {
		name          string
		before, after string
		want          []change
	}{
		{
			name: "order, ids and timestamps are not changes",
			before: `{"realm":"r","id":"1","clients":[
				{"id":"c1","clientId":"a","redirectUris":["https://x","https://y"]},
				{"id":"c2","clientId":"b"}],
				"users":[{"id":"u1","username":"alice","createdTimestamp":1,"credentials":[{"id":"k","type":"password","createdDate":5}]}]}`,
			after: `{"realm":"r","id":"2","clients":[
				{"id":"c9","clientId":"b"},
				{"id":"c8","clientId":"a","redirectUris":["https://y","https://x"]}],
				"users":[{"id":"u2","username":"alice","createdTimestamp":2,"credentials":[{"id":"z","type":"password","createdDate":6}]}]}`,
			want: []change{},
		},
		{
			name:   "scalar setting changed",
			before: `{"realm":"r","sslRequired":"external","accessTokenLifespan":300,"bruteForceProtected":true}`,
			after:  `{"realm":"r","sslRequired":"none","accessTokenLifespan":3600,"bruteForceProtected":true}`,
			want: []change{
				{Changed, "accessTokenLifespan", "300", "3600", false},
				{Changed, "sslRequired", `"external"`, `"none"`, false},
			},
		},
		{
			name:   "setting added and removed",
			before: `{"realm":"r","loginTheme":"acme"}`,
			after:  `{"realm":"r","emailTheme":"acme"}`,
			want: []change{
				{Added, "emailTheme", "", `"acme"`, false},
				{Removed, "loginTheme", `"acme"`, "", false},
			},
		},
		{
			name:   "client added, removed and changed",
			before: `{"realm":"r","clients":[{"clientId":"old"},{"clientId":"app","implicitFlowEnabled":false,"redirectUris":["https://a"]}]}`,
			after:  `{"realm":"r","clients":[{"clientId":"new"},{"clientId":"app","implicitFlowEnabled":true,"redirectUris":["https://a","*"]}]}`,
			want: []change{
				{Changed, `clients["app"].implicitFlowEnabled`, "false", "true", false},
				{Added, `clients["app"].redirectUris`, "", `"*"`, false},
				{Added, `clients["new"]`, "", "", false},
				{Removed, `clients["old"]`, "", "", false},
			},
		},
		{
			name:   "secrets are hidden",
			before: `{"realm":"r","clients":[{"clientId":"svc","secret":"one"}],"smtpServer":{"host":"mail","password":"p1"}}`,
			after:  `{"realm":"r","clients":[{"clientId":"svc","secret":"two"}],"smtpServer":{"host":"mail","password":"p2"}}`,
			want: []change{
				{Changed, `clients["svc"].secret`, "", "", true},
				{Changed, "smtpServer.password", "", "", true},
			},
		},
		{
			name:   "single-value component config changes in place",
			before: `{"realm":"r","components":{"org.keycloak.keys.KeyProvider":[{"name":"rsa","providerId":"rsa-generated","config":{"priority":["100"],"keySize":["2048"]}}]}}`,
			after:  `{"realm":"r","components":{"org.keycloak.keys.KeyProvider":[{"name":"rsa","providerId":"rsa-generated","config":{"priority":["100"],"keySize":["4096"]}}]}}`,
			want: []change{
				{Changed, `components["org.keycloak.keys.KeyProvider"]["rsa"].config.keySize`, `"2048"`, `"4096"`, false},
			},
		},
		{
			name: "items sharing a name are matched by name and subType",
			before: `{"realm":"r","components":{"policy":[
				{"name":"Max Clients","subType":"anonymous","config":{"max":["200"]}},
				{"name":"Max Clients","subType":"authenticated","config":{"max":["200"]}}]}}`,
			after: `{"realm":"r","components":{"policy":[
				{"name":"Max Clients","subType":"authenticated","config":{"max":["200"]}},
				{"name":"Max Clients","subType":"anonymous","config":{"max":["50"]}}]}}`,
			want: []change{
				{Changed, `components.policy["Max Clients/anonymous"].config.max`, `"200"`, `"50"`, false},
			},
		},
		{
			name:   "lists without identity compare as multisets",
			before: `{"realm":"r","authenticationFlows":[{"alias":"browser","authenticationExecutions":[{"authenticator":"cookie","priority":10},{"authenticator":"otp","priority":20}]}]}`,
			after:  `{"realm":"r","authenticationFlows":[{"alias":"browser","authenticationExecutions":[{"authenticator":"cookie","priority":10}]}]}`,
			want: []change{
				{Removed, `authenticationFlows["browser"].authenticationExecutions`, "", "", false},
			},
		},
		{
			name:   "map keys with dots are bracketed",
			before: `{"realm":"r","attributes":{"frontendUrl":"https://a"}}`,
			after:  `{"realm":"r","attributes":{"frontendUrl":"https://b","client.policy.x":"on"}}`,
			want: []change{
				{Added, `attributes["client.policy.x"]`, "", `"on"`, false},
				{Changed, "attributes.frontendUrl", `"https://a"`, `"https://b"`, false},
			},
		},
		{
			name:   "realms added and removed",
			before: `[{"realm":"keep"},{"realm":"gone"}]`,
			after:  `[{"realm":"keep"},{"realm":"fresh"}]`,
			want: []change{
				{Added, "", "", "", false},
				{Removed, "", "", "", false},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summarise(Compare(load(t, tt.before), load(t, tt.after)))
			if len(got) != len(tt.want) {
				t.Fatalf("got %d changes, want %d:\n%+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("change %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCompareSameVersionFixturesShowOnlyVersionChanges(t *testing.T) {
	before, err := realm.Load("../../testdata/realms/26.7.5/single.json")
	if err != nil {
		t.Fatal(err)
	}
	after, err := realm.Load("../../testdata/realms/26.8.0/single.json")
	if err != nil {
		t.Fatal(err)
	}
	// The same seed realm exported by two releases: the version, one default
	// 26.8 no longer writes, and keys each fixture run generated afresh.
	want := map[string]bool{
		"keycloakVersion": true,
		`clientScopes["web-origins"].attributes["consent.screen.text"]`:                       true,
		`components["org.keycloak.keys.KeyProvider"]["aes-generated"].config.kid`:             true,
		`components["org.keycloak.keys.KeyProvider"]["hmac-generated-hs512"].config.kid`:      true,
		`components["org.keycloak.keys.KeyProvider"]["rsa-enc-generated"].config.certificate`: true,
		`components["org.keycloak.keys.KeyProvider"]["rsa-generated"].config.certificate`:     true,
	}
	changes := Compare(before, after)
	for _, c := range changes {
		if !want[c.Path] {
			t.Errorf("unexpected change: %s %s", c.Kind, c.Path)
		}
		delete(want, c.Path)
	}
	for p := range want {
		t.Errorf("missing change at %s", p)
	}
}

func TestCompareFindings(t *testing.T) {
	f := func(checkID, object, msg string) check.Finding {
		return check.Finding{Realm: "r", CheckID: checkID, Object: object, Message: msg}
	}
	before := []check.Finding{f("a", "", "x"), f("b", "client", "lifespan 1h"), f("c", "", "same")}
	after := []check.Finding{f("c", "", "same"), f("b", "client", "lifespan 2h"), f("d", "", "y")}
	added, resolved := CompareFindings(before, after)
	if len(added) != 2 || added[0].Message != "lifespan 2h" || added[1].CheckID != "d" {
		t.Errorf("added = %+v", added)
	}
	if len(resolved) != 2 || resolved[0].CheckID != "a" || resolved[1].Message != "lifespan 1h" {
		t.Errorf("resolved = %+v", resolved)
	}
}
