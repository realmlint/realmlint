// Package report ranks findings and writes them as text or JSON.
package report

import (
	"sort"

	"github.com/realmlint/realmlint/internal/check"
	"github.com/realmlint/realmlint/internal/realm"
)

// Result is a ranked, filtered set of findings ready to print.
type Result struct {
	Realms []*realm.Realm
	// Findings are the findings to show: ranked, at or above MinSeverity,
	// and limited to Top when Top is set.
	Findings []check.Finding
	// Matched counts findings at or above MinSeverity, before Top applies.
	Matched int
	// Counts holds Matched broken down by severity.
	Counts map[check.Severity]int
	// Hidden counts findings below MinSeverity.
	Hidden int
	// Suppressed counts findings ignored by the configuration file. They
	// are not part of Findings.
	Suppressed  int
	MinSeverity check.Severity
	Top         int
}

// Build ranks findings, drops those below minSeverity and keeps the first
// top findings (all of them when top is 0).
func Build(realms []*realm.Realm, findings []check.Finding, minSeverity check.Severity, top int) Result {
	res := Result{
		Realms:      realms,
		Counts:      map[check.Severity]int{},
		MinSeverity: minSeverity,
		Top:         top,
	}
	var kept []check.Finding
	for _, f := range findings {
		if f.Severity < minSeverity {
			res.Hidden++
			continue
		}
		kept = append(kept, f)
		res.Counts[f.Severity]++
	}
	rank(kept, realms)
	res.Matched = len(kept)
	if top > 0 && top < len(kept) {
		kept = kept[:top]
	}
	res.Findings = kept
	return res
}

// rank orders findings by severity (highest first), then realm in load
// order, check in catalog order, and object.
func rank(findings []check.Finding, realms []*realm.Realm) {
	realmOrder := map[string]int{}
	for i, r := range realms {
		realmOrder[r.Realm] = i
	}
	checkOrder := map[string]int{}
	for i, c := range check.All() {
		checkOrder[c.ID] = i
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		switch {
		case a.Severity != b.Severity:
			return a.Severity > b.Severity
		case a.Realm != b.Realm:
			return realmOrder[a.Realm] < realmOrder[b.Realm]
		case a.CheckID != b.CheckID:
			return checkOrder[a.CheckID] < checkOrder[b.CheckID]
		default:
			return a.Object < b.Object
		}
	})
}
