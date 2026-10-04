// Command redact masks secret values in Keycloak export files in place.
//
// It is used by scripts/gen-fixtures.sh so generated test fixtures never
// contain private keys, client secrets or password hashes. Certificates are
// public and are kept, because expiry checks read them.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// mask is the value Keycloak itself uses when it hides secrets in exports.
const mask = "**********"

var secretKeys = map[string]bool{
	"privateKey":     true,
	"secret":         true,
	"secretData":     true,
	"credentialData": true,
	"clientSecret":   true,
	"password":       true,
	"bindCredential": true,
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: redact FILE...")
		os.Exit(2)
	}
	for _, path := range os.Args[1:] {
		if err := redactFile(path); err != nil {
			fmt.Fprintf(os.Stderr, "redact %s: %v\n", path, err)
			os.Exit(1)
		}
	}
}

func redactFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return err
	}
	out, err := json.MarshalIndent(redact(doc), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if secretKeys[k] {
				t[k] = maskValue(child)
				continue
			}
			t[k] = redact(child)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = redact(child)
		}
		return t
	default:
		return v
	}
}

// maskValue keeps the value's shape: component config values are string
// lists, everything else is a plain string.
func maskValue(v any) any {
	switch t := v.(type) {
	case []any:
		masked := make([]any, len(t))
		for i := range t {
			masked[i] = mask
		}
		return masked
	case string:
		return mask
	default:
		return v
	}
}
