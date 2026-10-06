package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/realmlint/realmlint/internal/check"
	"github.com/realmlint/realmlint/internal/realm"
)

func TestBuildRanksAcrossRealms(t *testing.T) {
	realms := []*realm.Realm{{Realm: "zeta"}, {Realm: "alpha"}}
	findings := []check.Finding{
		{CheckID: "full-scope-allowed", Severity: check.Low, Realm: "zeta", Object: "b"},
		{CheckID: "brute-force-disabled", Severity: check.Medium, Realm: "alpha"},
		{CheckID: "ssl-required-none", Severity: check.High, Realm: "alpha"},
		{CheckID: "full-scope-allowed", Severity: check.Low, Realm: "zeta", Object: "a"},
		{CheckID: "brute-force-disabled", Severity: check.Medium, Realm: "zeta"},
		{CheckID: "ssl-required-none", Severity: check.High, Realm: "zeta"},
	}
	res := Build(realms, findings, check.Low, 0)

	// Severity first, then realms in load order (zeta before alpha), then
	// check order, then object.
	want := []string{
		"high/zeta/ssl-required-none/",
		"high/alpha/ssl-required-none/",
		"medium/zeta/brute-force-disabled/",
		"medium/alpha/brute-force-disabled/",
		"low/zeta/full-scope-allowed/a",
		"low/zeta/full-scope-allowed/b",
	}
	for i, f := range res.Findings {
		got := f.Severity.String() + "/" + f.Realm + "/" + f.CheckID + "/" + f.Object
		if got != want[i] {
			t.Errorf("position %d = %s, want %s", i, got, want[i])
		}
	}
}

func TestBuildFiltersThenLimits(t *testing.T) {
	findings := []check.Finding{
		{CheckID: "a", Severity: check.Low, Realm: "r"},
		{CheckID: "b", Severity: check.Medium, Realm: "r"},
		{CheckID: "c", Severity: check.High, Realm: "r"},
		{CheckID: "d", Severity: check.Critical, Realm: "r"},
	}
	res := Build([]*realm.Realm{{Realm: "r"}}, findings, check.Medium, 2)
	if res.Matched != 3 || res.Hidden != 1 || len(res.Findings) != 2 {
		t.Fatalf("matched=%d hidden=%d shown=%d, want 3, 1, 2", res.Matched, res.Hidden, len(res.Findings))
	}
	if res.Findings[0].Severity != check.Critical || res.Findings[1].Severity != check.High {
		t.Errorf("kept %s and %s, want critical and high", res.Findings[0].Severity, res.Findings[1].Severity)
	}
}

func TestWriteWrapped(t *testing.T) {
	var b bytes.Buffer
	long := strings.Repeat("x", 100)
	writeWrapped(&b, "Why: ", "     ", "short words then "+long+" and more")
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), b.String())
	}
	if lines[0] != "Why: short words then" || lines[1] != "     "+long || lines[2] != "     and more" {
		t.Errorf("unexpected wrapping:\n%s", b.String())
	}
}
