// Command gendocs writes docs/checks.md from the check catalog.
package main

import (
	"fmt"
	"os"

	"github.com/realmlint/realmlint/pkg/check"
)

func main() {
	if err := os.WriteFile("docs/checks.md", []byte(check.CatalogMarkdown()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gendocs:", err)
		os.Exit(1)
	}
}
