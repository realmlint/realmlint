// Package upgrade lists what changes between two Keycloak versions, from
// Keycloak's upgrading guide, and checks realm configuration for the changes
// realmlint can see there.
//
// catalogue.json is extracted from the guide (sections "Migrating to 26.x")
// and keeps each change's title and opening sentences as written there, with
// the anchor to read the rest. Nothing in it is written by realmlint. The
// guide is Keycloak documentation, licensed under the Apache License 2.0.
package upgrade

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// GuideURL is the upgrading guide the catalogue comes from.
const GuideURL = "https://www.keycloak.org/docs/latest/upgrading/index.html"

//go:embed catalogue.json
var catalogueJSON []byte

// Item is one change from the guide.
type Item struct {
	Version  string `json:"version"`
	Category string `json:"category"` // breaking, notable, deprecated, removed
	Anchor   string `json:"anchor"`
	Title    string `json:"title"`
	Summary  string `json:"summary"`
}

// URL links to the item in the guide.
func (i Item) URL() string { return GuideURL + "#" + i.Anchor }

var catalogue = func() []Item {
	var c struct {
		Items []Item `json:"items"`
	}
	if err := json.Unmarshal(catalogueJSON, &c); err != nil {
		panic(err)
	}
	return c.Items
}()

// Catalogue returns every item, newest version first.
func Catalogue() []Item { return catalogue }

// Versions returns the versions the catalogue has changes for, newest first.
func Versions() []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range catalogue {
		if !seen[it.Version] {
			seen[it.Version] = true
			out = append(out, it.Version)
		}
	}
	sort.Slice(out, func(i, j int) bool { return Compare(out[i], out[j]) > 0 })
	return out
}

// Oldest is the earliest version the catalogue starts from: upgrades from
// any 26.x release are covered.
const Oldest = "26.0.0"

// Parse reads the major, minor and patch numbers of a Keycloak version such
// as "26.4.2" or "26.4.10.redhat-00001".
func Parse(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.SplitN(strings.TrimSpace(v), ".", 4)
	if len(parts) < 2 {
		return out, false
	}
	for i := 0; i < 3 && i < len(parts); i++ {
		digits := parts[i]
		if end := strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }); end >= 0 {
			digits = digits[:end]
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Compare orders two versions: negative when a is older than b.
func Compare(a, b string) int {
	pa, _ := Parse(a)
	pb, _ := Parse(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] - pb[i]
		}
	}
	return 0
}

// Hit is one object a change affects.
type Hit struct {
	Realm  string `json:"realm"`
	Object string `json:"object"` // e.g. "Client portal"
	Detail string `json:"detail"`
}

// Status says what realmlint knows about an item for these realms.
const (
	Affected = "affected" // a check found objects the change affects
	Clear    = "clear"    // a check ran and found nothing
	Manual   = "manual"   // realm snapshots cannot show it; read it
)

// Advice is an item with what the checks found.
type Advice struct {
	Item
	URL     string `json:"url"`
	Status  string `json:"status"`
	Checked string `json:"checked,omitempty"` // what the check looks at
	Hits    []Hit  `json:"hits"`
}

// Report is the advice for one upgrade.
type Report struct {
	From  string   `json:"from"`
	To    string   `json:"to"`
	Items []Advice `json:"items"`
}

// Advise returns the guide's changes after from up to and including to, with
// each check run against the realms (realm name to the realm export, decoded
// as generic JSON). Affected
// items come first, then breaking and removed changes, then the rest; each
// group keeps the guide's order.
func Advise(from, to string, realms map[string]map[string]any) (Report, error) {
	if _, ok := Parse(from); !ok {
		return Report{}, fmt.Errorf("version %q is not a Keycloak version", from)
	}
	if _, ok := Parse(to); !ok {
		return Report{}, fmt.Errorf("version %q is not a Keycloak version", to)
	}
	names := make([]string, 0, len(realms))
	parsed := map[string]realm{}
	for name, doc := range realms {
		names = append(names, name)
		parsed[name] = realm{name: name, data: doc}
	}
	sort.Strings(names)

	rep := Report{From: from, To: to, Items: []Advice{}}
	for _, it := range catalogue {
		if Compare(it.Version, from) <= 0 || Compare(it.Version, to) > 0 {
			continue
		}
		a := Advice{Item: it, URL: it.URL(), Status: Manual, Hits: []Hit{}}
		if c, ok := checks[it.Anchor]; ok {
			a.Status, a.Checked = Clear, c.looksAt
			for _, name := range names {
				a.Hits = append(a.Hits, c.run(parsed[name])...)
			}
			if len(a.Hits) > 0 {
				a.Status = Affected
			}
		}
		rep.Items = append(rep.Items, a)
	}
	sort.SliceStable(rep.Items, func(i, j int) bool { return rank(rep.Items[i]) < rank(rep.Items[j]) })
	return rep, nil
}

func rank(a Advice) int {
	switch {
	case a.Status == Affected:
		return 0
	case a.Category == "breaking" || a.Category == "removed":
		return 1
	case a.Category == "deprecated":
		return 2
	default:
		return 3
	}
}
