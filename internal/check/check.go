// Package check runs realmlint's checks against loaded realms.
//
// Each check looks at one realm at a time and reports findings. A check
// carries the static explanation and fix steps; findings carry what was
// found and where.
package check

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/edzordzinam/realmlint/internal/realm"
)

// Severity ranks how urgent a finding is.
type Severity int

// Severities, lowest first.
const (
	Low Severity = iota + 1
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	default:
		return fmt.Sprintf("severity(%d)", int(s))
	}
}

// MarshalText implements encoding.TextMarshaler, so severities appear as
// names in JSON.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// ParseSeverity converts a severity name such as "high" to a Severity.
func ParseSeverity(name string) (Severity, error) {
	for s := Low; s <= Critical; s++ {
		if s.String() == strings.ToLower(name) {
			return s, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (use low, medium, high or critical)", name)
}

// Finding is one problem in one realm.
type Finding struct {
	CheckID  string
	Title    string
	Severity Severity
	Realm    string
	// Object is what the finding is about, such as `client "web-spa"`.
	// It is empty for realm-wide settings.
	Object string
	// Message states what was found, with the actual values.
	Message string
	// Why explains the risk and Fix says how to resolve it; both come from
	// the check.
	Why string
	Fix string
	// Source is the export file the realm was loaded from.
	Source string
	// Setting is copied from the check; see Check.Setting.
	Setting string
}

// Check is one rule.
type Check struct {
	ID    string
	Title string
	Why   string
	Fix   string
	// Setting is the realm export field that realm-wide findings of this
	// check are about, such as "sslRequired". It is used to point at the
	// right line in the export.
	Setting string
	Run     func(*Context) []Finding
}

// Context is what a check sees.
type Context struct {
	Realm *realm.Realm
	// Realms is every realm loaded in this run, for checks that compare
	// realms.
	Realms []*realm.Realm
	Now    time.Time
}

// All returns every check in a stable order.
func All() []Check {
	var all []Check
	all = append(all, realmChecks...)
	all = append(all, tokenChecks...)
	all = append(all, clientChecks...)
	all = append(all, accessChecks...)
	all = append(all, expiryChecks...)
	return all
}

// Run runs checks against every realm and returns the findings in realm
// order, then check order.
func Run(realms []*realm.Realm, checks []Check, now time.Time) []Finding {
	var findings []Finding
	for _, r := range realms {
		ctx := &Context{Realm: r, Realms: realms, Now: now}
		for _, c := range checks {
			for _, f := range c.Run(ctx) {
				f.CheckID = c.ID
				f.Title = c.Title
				f.Realm = r.Realm
				f.Why = c.Why
				f.Fix = c.Fix
				f.Source = r.Source
				f.Setting = c.Setting
				findings = append(findings, f)
			}
		}
	}
	return findings
}

func clientObject(c *realm.Client) string {
	return fmt.Sprintf("client %q", c.ClientID)
}

func userObject(u *realm.User) string {
	if u.IsServiceAccount() {
		return fmt.Sprintf("service account of client %q", u.ServiceAccountClientID)
	}
	return fmt.Sprintf("user %q", u.Username)
}

// humanDuration formats seconds in the largest whole unit.
func humanDuration(seconds int) string {
	switch {
	case seconds != 0 && seconds%86400 == 0:
		return plural(seconds/86400, "day")
	case seconds != 0 && seconds%3600 == 0:
		return plural(seconds/3600, "hour")
	case seconds != 0 && seconds%60 == 0:
		return plural(seconds/60, "minute")
	default:
		return plural(seconds, "second")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// objectPatterns map the Object formats above to the export field and value
// that identify the object.
var objectPatterns = []struct {
	re    *regexp.Regexp
	field string
}{
	{regexp.MustCompile(`^service account of client ("(?:[^"\\]|\\.)*")$`), "serviceAccountClientId"},
	{regexp.MustCompile(`^client ("(?:[^"\\]|\\.)*")$`), "clientId"},
	{regexp.MustCompile(`^user ("(?:[^"\\]|\\.)*")$`), "username"},
	{regexp.MustCompile(`^identity provider ("(?:[^"\\]|\\.)*")$`), "alias"},
	{regexp.MustCompile(`^key ("(?:[^"\\]|\\.)*") \(`), "name"},
}

// Locate returns the export field (and its value, for objects) that a
// finding is about, such as ("clientId", "web-spa") or ("sslRequired", "").
// Both are empty when the finding cannot be tied to a field.
func (f Finding) Locate() (field, value string) {
	for _, p := range objectPatterns {
		if m := p.re.FindStringSubmatch(f.Object); m != nil {
			if v, err := strconv.Unquote(m[1]); err == nil {
				return p.field, v
			}
		}
	}
	if f.Object == "" {
		return f.Setting, ""
	}
	return "", ""
}
