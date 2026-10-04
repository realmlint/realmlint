// Package diff compares two sets of realm exports and reports meaningful
// configuration changes.
//
// It works on the raw export JSON so every setting is compared, including
// ones the checks do not model. Lists of objects are matched by their
// identity field (clientId, username, alias or name) instead of position,
// lists of strings are compared as sets, and internal IDs and timestamps
// are ignored. Secret values are never reported, only that they changed.
package diff

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/edzordzinam/realmlint/internal/realm"
)

// Kind says how a value changed.
type Kind string

// Change kinds.
const (
	Added   Kind = "added"
	Removed Kind = "removed"
	Changed Kind = "changed"
)

// Change is one difference between the before and after exports.
type Change struct {
	Realm string
	// Path locates the value, such as `clients["web-spa"].redirectUris`.
	// It is empty when a whole realm was added or removed.
	Path string
	Kind Kind
	// Before and After hold scalar values. They are nil for objects, for
	// the missing side of an addition or removal, and for hidden values.
	Before any
	After  any
	// Hidden is set for secrets and certificates, whose values are not
	// shown.
	Hidden bool
}

// ignoredKeys are internal identifiers and timestamps that differ between
// exports of the same configuration.
var ignoredKeys = map[string]bool{
	"id":                          true,
	"internalId":                  true,
	"containerId":                 true,
	"createdTimestamp":            true,
	"createdDate":                 true,
	"notBefore":                   true,
	"parentId":                    true,
	"client.secret.creation.time": true,
}

// hiddenKeys hold secrets, or certificates too long to be useful in a diff.
var hiddenKeys = map[string]bool{
	"privateKey":     true,
	"certificate":    true,
	"secret":         true,
	"secretData":     true,
	"credentialData": true,
	"clientSecret":   true,
	"password":       true,
	"bindCredential": true,
}

// identities are tried in order to match list items between exports. An
// identity with several fields is used when the first alone is not unique,
// such as client registration policies that share a name.
var identities = [][]string{
	{"clientId"},
	{"username"},
	{"alias"},
	{"name"},
	{"name", "subType"},
	{"type"},
}

// Compare returns the changes from before to after, realm by realm. Realms
// are matched by name and reported in the order they appear in after, then
// removed realms in the order they appear in before.
func Compare(before, after []*realm.Realm) []Change {
	beforeByName := map[string]*realm.Realm{}
	for _, r := range before {
		beforeByName[r.Realm] = r
	}
	afterNames := map[string]bool{}

	var changes []Change
	for _, a := range after {
		afterNames[a.Realm] = true
		b, ok := beforeByName[a.Realm]
		if !ok {
			changes = append(changes, Change{Realm: a.Realm, Kind: Added})
			continue
		}
		c := &comparer{realm: a.Realm}
		c.compare("", "", b.Raw, a.Raw)
		changes = append(changes, c.changes...)
	}
	for _, b := range before {
		if !afterNames[b.Realm] {
			changes = append(changes, Change{Realm: b.Realm, Kind: Removed})
		}
	}
	return changes
}

type comparer struct {
	realm   string
	changes []Change
}

func (c *comparer) add(path, key string, kind Kind, before, after any) {
	ch := Change{Realm: c.realm, Path: path, Kind: kind}
	switch {
	case hiddenKeys[key]:
		ch.Hidden = true
	default:
		if isScalar(before) {
			ch.Before = before
		}
		if isScalar(after) {
			ch.After = after
		}
	}
	c.changes = append(c.changes, ch)
}

// compare records the differences between a and b at path. key is the last
// object field on the path, used to recognise secrets.
func (c *comparer) compare(path, key string, a, b any) {
	switch av := a.(type) {
	case map[string]any:
		if bv, ok := b.(map[string]any); ok {
			c.compareMaps(path, av, bv)
			return
		}
	case []any:
		if bv, ok := b.([]any); ok {
			c.compareLists(path, key, av, bv)
			return
		}
	}
	if !equal(a, b) {
		c.add(path, key, Changed, a, b)
	}
}

func (c *comparer) compareMaps(path string, a, b map[string]any) {
	for _, k := range unionKeys(a, b) {
		if ignoredKeys[k] {
			continue
		}
		p := joinField(path, k)
		av, inA := a[k]
		bv, inB := b[k]
		switch {
		case !inA:
			c.add(p, k, Added, nil, bv)
		case !inB:
			c.add(p, k, Removed, av, nil)
		default:
			c.compare(p, k, av, bv)
		}
	}
}

func (c *comparer) compareLists(path, key string, a, b []any) {
	// Single values, such as component config entries, change in place.
	if len(a) == 1 && len(b) == 1 && isScalar(a[0]) && isScalar(b[0]) {
		if !equal(a[0], b[0]) {
			c.add(path, key, Changed, a[0], b[0])
		}
		return
	}
	if fields := identity(a, b); fields != nil {
		am, bm := indexBy(a, fields), indexBy(b, fields)
		for _, id := range unionKeys(am, bm) {
			p := fmt.Sprintf("%s[%q]", path, id)
			av, inA := am[id]
			bv, inB := bm[id]
			switch {
			case !inA:
				c.add(p, key, Added, nil, bv)
			case !inB:
				c.add(p, key, Removed, av, nil)
			default:
				c.compare(p, key, av, bv)
			}
		}
		return
	}

	// Without an identity field, compare as multisets: scalars by value,
	// objects by their canonical JSON.
	counts := map[string]int{}
	values := map[string]any{}
	for _, v := range a {
		k := canonical(v)
		counts[k]--
		values[k] = v
	}
	for _, v := range b {
		k := canonical(v)
		counts[k]++
		values[k] = v
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for n := counts[k]; n > 0; n-- {
			c.add(path, key, Added, nil, values[k])
		}
		for n := counts[k]; n < 0; n++ {
			c.add(path, key, Removed, values[k], nil)
		}
	}
}

// identity returns the first identity whose fields every item in both
// lists has, forming a key that is unique within each list.
func identity(a, b []any) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	for _, fields := range identities {
		if uniqueKeys(a, fields) && uniqueKeys(b, fields) {
			return fields
		}
	}
	return nil
}

func uniqueKeys(items []any, fields []string) bool {
	seen := map[string]bool{}
	for _, it := range items {
		k, ok := itemKey(it, fields)
		if !ok || seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}

// itemKey joins the item's identity fields with "/". Every field must be a
// non-empty string.
func itemKey(item any, fields []string) (string, bool) {
	m, ok := item.(map[string]any)
	if !ok {
		return "", false
	}
	parts := make([]string, len(fields))
	for i, f := range fields {
		s, ok := m[f].(string)
		if !ok || s == "" {
			return "", false
		}
		parts[i] = s
	}
	return strings.Join(parts, "/"), true
}

func indexBy(items []any, fields []string) map[string]any {
	out := make(map[string]any, len(items))
	for _, it := range items {
		k, _ := itemKey(it, fields)
		out[k] = it
	}
	return out
}

func unionKeys[V any](a, b map[string]V) []string {
	seen := map[string]bool{}
	var keys []string
	for k := range a {
		seen[k] = true
		keys = append(keys, k)
	}
	for k := range b {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// joinField appends an object field to a path, as .field for plain names
// and ["field"] for names with dots, dashes or spaces.
func joinField(path, field string) string {
	if !plainName.MatchString(field) {
		return fmt.Sprintf("%s[%q]", path, field)
	}
	if path == "" {
		return field
	}
	return path + "." + field
}

var plainName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func isScalar(v any) bool {
	switch v.(type) {
	case map[string]any, []any, nil:
		return false
	}
	return true
}

func equal(a, b any) bool {
	return reflect.DeepEqual(a, b)
}

// canonical returns v as JSON with sorted keys, ignoring internal IDs and
// timestamps, so equal configurations compare equal.
func canonical(v any) string {
	out, _ := json.Marshal(stripIgnored(v))
	return string(out)
}

func stripIgnored(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, child := range t {
			if !ignoredKeys[k] {
				m[k] = stripIgnored(child)
			}
		}
		return m
	case []any:
		items := make([]any, len(t))
		for i, child := range t {
			items[i] = stripIgnored(child)
		}
		return items
	}
	return v
}

// FormatValue renders a scalar for display: strings quoted, long values
// shortened.
func FormatValue(v any) string {
	var s string
	switch t := v.(type) {
	case string:
		s = fmt.Sprintf("%q", t)
	case json.Number:
		s = t.String()
	default:
		b, _ := json.Marshal(t)
		s = string(b)
	}
	const maxLen = 60
	if len(s) > maxLen {
		s = s[:maxLen-3] + "..."
	}
	return strings.ReplaceAll(s, "\n", " ")
}
