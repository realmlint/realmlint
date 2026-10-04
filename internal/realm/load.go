package realm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// utf8BOM is stripped from input; editors on Windows often add it.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// usersFile is a separate users file written by
// `kc.sh export --dir ... --users different_files`.
type usersFile struct {
	Realm string `json:"realm"`
	Users []User `json:"users"`
	path  string
}

// Load reads realm exports from files and directories and returns the
// realms they contain, in input order.
//
// It accepts the three formats kc.sh export produces: a single realm object,
// an array of realms, and a directory of <realm>-realm.json files with
// optional <realm>-users-N.json files. Users files are merged into their
// realm. A directory is read one level deep, taking every *.json file.
func Load(paths ...string) ([]*Realm, error) {
	files, err := expand(paths)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("no realm export files given")
	}

	var realms []*Realm
	var users []usersFile
	byName := map[string]*Realm{}

	for _, path := range files {
		rs, uf, err := parseFile(path)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			if prev, ok := byName[r.Realm]; ok {
				return nil, fmt.Errorf("%s: realm %q is also defined in %s", path, r.Realm, prev.Source)
			}
			byName[r.Realm] = r
			realms = append(realms, r)
		}
		if uf != nil {
			users = append(users, *uf)
		}
	}

	for _, uf := range users {
		r, ok := byName[uf.Realm]
		if !ok {
			return nil, fmt.Errorf("%s: users file for realm %q, but no export for that realm was given", uf.path, uf.Realm)
		}
		r.Users = append(r.Users, uf.Users...)
	}
	return realms, nil
}

// expand replaces directories with the *.json files directly inside them,
// sorted by name.
func expand(paths []string) ([]string, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		matches, err := filepath.Glob(filepath.Join(p, "*.json"))
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("%s: directory contains no .json files", p)
		}
		sort.Strings(matches)
		files = append(files, matches...)
	}
	return files, nil
}

// parseFile returns either the realms in a file or its users file content.
func parseFile(path string) ([]*Realm, *usersFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	data = bytes.TrimSpace(bytes.TrimPrefix(data, utf8BOM))
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("%s: file is empty", path)
	}

	switch data[0] {
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, nil, fmt.Errorf("%s: invalid JSON: %w", path, err)
		}
		realms := make([]*Realm, 0, len(items))
		for i, item := range items {
			r, err := parseRealm(item)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: item %d: %w", path, i, err)
			}
			r.Source = path
			realms = append(realms, r)
		}
		return realms, nil, nil

	case '{':
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(data, &keys); err != nil {
			return nil, nil, fmt.Errorf("%s: invalid JSON: %w", path, err)
		}
		if isUsersFile(keys) {
			var uf usersFile
			if err := json.Unmarshal(data, &uf); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", path, err)
			}
			uf.path = path
			return nil, &uf, nil
		}
		r, err := parseRealm(data)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		r.Source = path
		return []*Realm{r}, nil, nil

	default:
		return nil, nil, fmt.Errorf("%s: not a JSON object or array", path)
	}
}

func parseRealm(data []byte) (*Realm, error) {
	var r Realm
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("not a Keycloak realm export: %w", err)
	}
	if r.Realm == "" {
		return nil, errors.New(`not a Keycloak realm export: missing "realm" name`)
	}
	return &r, nil
}

// isUsersFile reports whether an object holds only a realm name and users,
// which is the shape of a separate users file.
func isUsersFile(keys map[string]json.RawMessage) bool {
	if _, ok := keys["realm"]; !ok {
		return false
	}
	_, hasUsers := keys["users"]
	_, hasFederated := keys["federatedUsers"]
	if !hasUsers && !hasFederated {
		return false
	}
	for k := range keys {
		switch k {
		case "realm", "users", "federatedUsers":
		default:
			return false
		}
	}
	return true
}
