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

	"github.com/realmlint/realmlint/pkg/redact"
)

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
	out, err := json.MarshalIndent(redact.Value(doc), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}
