// Package config reads the realmlint configuration file, which lists
// findings to ignore.
//
// Example .realmlint.yaml:
//
//	ignore:
//	  - check: full-scope-allowed
//	    realm: acme
//	    object: 'client "admin-ui"'
//	    reason: The admin UI needs every role the user has.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"

	"github.com/realmlint/realmlint/pkg/check"
)

// DefaultFile is read from the working directory when no file is given.
const DefaultFile = ".realmlint.yaml"

// Config is the parsed configuration file.
type Config struct {
	Ignore []Ignore `yaml:"ignore"`
	// Path is the file the configuration was read from; empty when no file
	// was used.
	Path string `yaml:"-"`
}

// Ignore suppresses findings of one check, optionally only in one realm or
// on one object. Object is matched exactly as realmlint prints it, such as
// `client "web-spa"`.
type Ignore struct {
	Check  string `yaml:"check"`
	Realm  string `yaml:"realm"`
	Object string `yaml:"object"`
	Reason string `yaml:"reason"`
}

// Matches reports whether the entry suppresses f.
func (ig Ignore) Matches(f check.Finding) bool {
	return ig.Check == f.CheckID &&
		(ig.Realm == "" || ig.Realm == f.Realm) &&
		(ig.Object == "" || ig.Object == f.Object)
}

// Load reads the configuration. With an empty path it reads DefaultFile if
// it exists and returns an empty configuration if it does not.
func Load(path string) (*Config, error) {
	explicit := path != ""
	if !explicit {
		path = DefaultFile
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, err
	}
	cfg, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path = path
	return cfg, nil
}

func parse(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	known := map[string]bool{}
	for _, c := range check.All() {
		known[c.ID] = true
	}
	for i, ig := range cfg.Ignore {
		switch {
		case ig.Check == "":
			return nil, fmt.Errorf("ignore entry %d: check is required", i+1)
		case !known[ig.Check]:
			return nil, fmt.Errorf("ignore entry %d: unknown check %q", i+1, ig.Check)
		case ig.Reason == "":
			return nil, fmt.Errorf("ignore entry %d (%s): reason is required", i+1, ig.Check)
		}
	}
	return &cfg, nil
}

// Apply splits findings into those to report and the number suppressed. It
// also returns the ignore entries that matched nothing, which are usually
// stale.
func (c *Config) Apply(findings []check.Finding) (kept []check.Finding, suppressed int, unused []Ignore) {
	used := make([]bool, len(c.Ignore))
	for _, f := range findings {
		matched := false
		for i, ig := range c.Ignore {
			if ig.Matches(f) {
				used[i] = true
				matched = true
			}
		}
		if matched {
			suppressed++
			continue
		}
		kept = append(kept, f)
	}
	for i, ig := range c.Ignore {
		if !used[i] {
			unused = append(unused, ig)
		}
	}
	return kept, suppressed, unused
}
