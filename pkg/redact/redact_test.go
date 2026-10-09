package redact

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

func decode(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

const sample = `{
  "realm": "acme",
  "clients": [{"clientId": "svc", "secret": "s3cret", "attributes": {"x": "1"}}],
  "users": [{"username": "a", "credentials": [{"type": "password", "secretData": "{\"value\":\"hash\"}", "credentialData": "{}"}]}],
  "identityProviders": [{"alias": "corp", "config": {"clientSecret": "idp-secret", "clientId": "rp"}}],
  "components": {"org.keycloak.keys.KeyProvider": [{"name": "rsa", "config": {"privateKey": ["MIIE..."], "certificate": ["MIIC..."]}}]},
  "smtpServer": {"host": "mail", "password": "smtp-pass"},
  "emptySecret": {"secret": ""}
}`

func TestLeaksFindsEverySecret(t *testing.T) {
	got := Leaks(decode(t, sample))
	sort.Strings(got)
	want := []string{
		"clients[].secret",
		"components.org.keycloak.keys.KeyProvider[].config.privateKey",
		"identityProviders[].config.clientSecret",
		"smtpServer.password",
		"users[].credentials[].credentialData",
		"users[].credentials[].secretData",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("leaks:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestValueMasksSecretsAndKeepsCertificates(t *testing.T) {
	v := Value(decode(t, sample))
	if leaks := Leaks(v); len(leaks) != 0 {
		t.Fatalf("secrets left after masking: %v", leaks)
	}
	out, _ := json.Marshal(v)
	s := string(out)
	for _, secret := range []string{"s3cret", "hash", "idp-secret", "MIIE", "smtp-pass"} {
		if strings.Contains(s, secret) {
			t.Errorf("masked output still contains %q", secret)
		}
	}
	for _, keep := range []string{"MIIC...", `"clientId":"rp"`, `"host":"mail"`, `"secret":""`} {
		if !strings.Contains(s, keep) {
			t.Errorf("masked output lost %q", keep)
		}
	}
}
