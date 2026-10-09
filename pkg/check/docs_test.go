package check

import (
	"os"
	"testing"
)

func TestCatalogDocsAreCurrent(t *testing.T) {
	got, err := os.ReadFile("../../docs/checks.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != CatalogMarkdown() {
		t.Error("docs/checks.md is out of date; run `go run ./tools/gendocs`")
	}
}
