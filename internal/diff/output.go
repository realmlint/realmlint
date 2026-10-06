package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/realmlint/realmlint/internal/check"
	"github.com/realmlint/realmlint/internal/report"
)

// Result is a comparison ready to print.
type Result struct {
	Changes []Change
	// NewFindings are findings in the after exports that were not in the
	// before exports; ResolvedFindings the reverse.
	NewFindings      []check.Finding
	ResolvedFindings []check.Finding
}

// CompareFindings returns findings that appear only in after (new) and only
// in before (resolved). Findings match on realm, check, object and message,
// so a changed value shows as one new and one resolved finding.
func CompareFindings(before, after []check.Finding) (added, resolved []check.Finding) {
	key := func(f check.Finding) string {
		return strings.Join([]string{f.Realm, f.CheckID, f.Object, f.Message}, "\x00")
	}
	count := map[string]int{}
	for _, f := range before {
		count[key(f)]++
	}
	for _, f := range after {
		k := key(f)
		if count[k] > 0 {
			count[k]--
			continue
		}
		added = append(added, f)
	}
	count = map[string]int{}
	for _, f := range after {
		count[key(f)]++
	}
	for _, f := range before {
		k := key(f)
		if count[k] > 0 {
			count[k]--
			continue
		}
		resolved = append(resolved, f)
	}
	return added, resolved
}

// Text writes the result for a terminal.
func Text(w io.Writer, res Result) {
	fmt.Fprintln(w, summary(res))

	var realm string
	for _, c := range res.Changes {
		if c.Realm != realm {
			realm = c.Realm
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Realm %s\n", realm)
		}
		fmt.Fprintf(w, "  %s\n", describe(c))
	}

	writeFindings(w, "New findings", res.NewFindings)
	writeFindings(w, "Resolved findings", res.ResolvedFindings)
}

func describe(c Change) string {
	if c.Path == "" {
		return fmt.Sprintf("%s whole realm %s", symbol(c.Kind), c.Kind)
	}
	switch {
	case c.Hidden:
		return fmt.Sprintf("%s %s (value hidden)", symbol(c.Kind), c.Path)
	case c.Kind == Changed:
		return fmt.Sprintf("~ %s: %s -> %s", c.Path, displayValue(c.Before), displayValue(c.After))
	case c.Kind == Added && c.After != nil:
		return fmt.Sprintf("+ %s: %s", c.Path, FormatValue(c.After))
	case c.Kind == Removed && c.Before != nil:
		return fmt.Sprintf("- %s: %s", c.Path, FormatValue(c.Before))
	default:
		return fmt.Sprintf("%s %s", symbol(c.Kind), c.Path)
	}
}

func displayValue(v any) string {
	if v == nil {
		return "(object)"
	}
	return FormatValue(v)
}

func symbol(k Kind) string {
	switch k {
	case Added:
		return "+"
	case Removed:
		return "-"
	default:
		return "~"
	}
}

func writeFindings(w io.Writer, heading string, findings []check.Finding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, heading)
	for _, f := range findings {
		where := f.Realm
		if f.Object != "" {
			where += ", " + f.Object
		}
		fmt.Fprintf(w, "  %-8s  %s [%s]\n", strings.ToUpper(f.Severity.String()), f.Title, f.CheckID)
		fmt.Fprintf(w, "            %s: %s\n", where, f.Message)
	}
}

func summary(res Result) string {
	if len(res.Changes) == 0 {
		return "No changes."
	}
	realms := map[string]bool{}
	for _, c := range res.Changes {
		realms[c.Realm] = true
	}
	return fmt.Sprintf("%s in %s. %s, %d resolved.",
		plural(len(res.Changes), "change"), plural(len(realms), "realm"),
		plural(len(res.NewFindings), "new finding"), len(res.ResolvedFindings))
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// SchemaVersion is the version of the diff JSON format.
const SchemaVersion = 1

type jsonDiff struct {
	SchemaVersion    int                  `json:"schemaVersion"`
	Tool             report.ToolJSON      `json:"tool"`
	Summary          jsonSummary          `json:"summary"`
	Changes          []jsonChange         `json:"changes"`
	NewFindings      []report.FindingJSON `json:"newFindings"`
	ResolvedFindings []report.FindingJSON `json:"resolvedFindings"`
}

type jsonSummary struct {
	Changes          int `json:"changes"`
	NewFindings      int `json:"newFindings"`
	ResolvedFindings int `json:"resolvedFindings"`
}

type jsonChange struct {
	Realm  string `json:"realm"`
	Path   string `json:"path,omitempty"`
	Kind   Kind   `json:"kind"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
	Hidden bool   `json:"hidden,omitempty"`
}

// JSON writes the result as an indented JSON document.
func JSON(w io.Writer, res Result, version string) error {
	out := jsonDiff{
		SchemaVersion: SchemaVersion,
		Tool:          report.ToolJSON{Name: "realmlint", Version: version},
		Summary: jsonSummary{
			Changes:          len(res.Changes),
			NewFindings:      len(res.NewFindings),
			ResolvedFindings: len(res.ResolvedFindings),
		},
		Changes:          make([]jsonChange, 0, len(res.Changes)),
		NewFindings:      make([]report.FindingJSON, 0, len(res.NewFindings)),
		ResolvedFindings: make([]report.FindingJSON, 0, len(res.ResolvedFindings)),
	}
	for _, c := range res.Changes {
		out.Changes = append(out.Changes, jsonChange(c))
	}
	for _, f := range res.NewFindings {
		out.NewFindings = append(out.NewFindings, report.NewFindingJSON(f))
	}
	for _, f := range res.ResolvedFindings {
		out.ResolvedFindings = append(out.ResolvedFindings, report.NewFindingJSON(f))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
