package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTemplateIsCurrent fails when the template no longer matches the
// script; run go run ./tools/gengitlab from the repository root.
func TestTemplateIsCurrent(t *testing.T) {
	root := filepath.Join("..", "..")
	script, err := os.ReadFile(filepath.Join(root, scriptPath))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, templatePath))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != render(string(script)) {
		t.Errorf("%s is out of date: run go run ./tools/gengitlab", templatePath)
	}
}
