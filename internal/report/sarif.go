package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/edzordzinam/realmlint/internal/check"
)

// DocsURL is where each check is documented; check IDs are anchors.
const DocsURL = "https://github.com/realmlint/realmlint/blob/main/docs/checks.md"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	Help             sarifText      `json:"help"`
	HelpURI          string         `json:"helpUri"`
	Properties       map[string]any `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// SARIF writes the result as SARIF 2.1.0 for GitHub code scanning and other
// tools. Each finding points at the export file and, where it can be found,
// the line of the setting or object it is about.
func SARIF(w io.Writer, res Result, version string) error {
	checks := check.All()
	ruleIndex := map[string]int{}
	rules := make([]sarifRule, len(checks))
	for i, c := range checks {
		ruleIndex[c.ID] = i
		rules[i] = sarifRule{
			ID:               c.ID,
			Name:             c.Title,
			ShortDescription: sarifText{c.Title},
			FullDescription:  sarifText{c.Why},
			Help:             sarifText{c.Fix},
			HelpURI:          DocsURL + "#" + c.ID,
			Properties:       map[string]any{"tags": []string{"security", "keycloak"}},
		}
	}

	loc := &locator{files: map[string][]byte{}}
	results := make([]sarifResult, 0, len(res.Findings))
	for _, f := range res.Findings {
		text := f.Message
		if f.Object != "" {
			text = f.Object + ": " + text
		}
		text = "Realm " + f.Realm + ": " + text + ". " + f.Fix
		results = append(results, sarifResult{
			RuleID:    f.CheckID,
			RuleIndex: ruleIndex[f.CheckID],
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{text},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: sarifURI(f.Source)},
				Region:           sarifRegion{StartLine: loc.line(f)},
			}}},
			PartialFingerprints: map[string]string{"realmlintFinding/v1": fingerprint(f)},
			Properties:          map[string]any{"severity": f.Severity.String(), "realm": f.Realm},
		})
	}

	out := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "realmlint",
				Version:        version,
				InformationURI: "https://github.com/realmlint/realmlint",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func sarifLevel(s check.Severity) string {
	switch s {
	case check.Critical, check.High:
		return "error"
	case check.Medium:
		return "warning"
	default:
		return "note"
	}
}

// sarifURI returns a relative path with forward slashes, or a file URI for
// absolute paths.
func sarifURI(path string) string {
	p := filepath.ToSlash(filepath.Clean(path))
	if filepath.IsAbs(path) {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p // Windows drive paths
		}
		return "file://" + p
	}
	return p
}

// fingerprint identifies a finding across runs so code scanning keeps one
// alert for it instead of opening a new one each time.
func fingerprint(f check.Finding) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{f.CheckID, f.Realm, f.Object, f.Message}, "\x00")))
	return hex.EncodeToString(sum[:16])
}

// locator finds the line a finding refers to in its export file.
type locator struct {
	files map[string][]byte
}

// line returns the line of the finding's field in its realm: the first
// match after the realm's name, or the first match in the file. It falls
// back to the realm's name, then to line 1.
func (l *locator) line(f check.Finding) int {
	data, ok := l.files[f.Source]
	if !ok {
		data, _ = os.ReadFile(f.Source)
		l.files[f.Source] = data
	}
	if len(data) == 0 {
		return 1
	}

	realmAt := firstIndex(fieldPattern("realm", f.Realm, true), data, 0)
	if field, value := f.Locate(); field != "" {
		re := fieldPattern(field, value, value != "")
		if at := firstIndex(re, data, max(realmAt, 0)); at >= 0 {
			return lineOf(data, at)
		}
		if at := firstIndex(re, data, 0); at >= 0 {
			return lineOf(data, at)
		}
	}
	if realmAt >= 0 {
		return lineOf(data, realmAt)
	}
	return 1
}

// fieldPattern matches `"field" : "value"` in pretty-printed or compact
// JSON, or just `"field" :` when withValue is false.
func fieldPattern(field, value string, withValue bool) *regexp.Regexp {
	key, _ := json.Marshal(field)
	pattern := regexp.QuoteMeta(string(key)) + `\s*:\s*`
	if withValue {
		v, _ := json.Marshal(value)
		pattern += regexp.QuoteMeta(string(v))
	}
	return regexp.MustCompile(pattern)
}

func firstIndex(re *regexp.Regexp, data []byte, from int) int {
	loc := re.FindIndex(data[from:])
	if loc == nil {
		return -1
	}
	return from + loc[0]
}

func lineOf(data []byte, offset int) int {
	return bytes.Count(data[:offset], []byte("\n")) + 1
}
