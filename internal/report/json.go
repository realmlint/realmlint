package report

import (
	"encoding/json"
	"io"

	"github.com/edzordzinam/realmlint/internal/check"
)

// SchemaVersion is the version of the JSON output format. Increase it when
// a field is removed or changes meaning; adding fields does not need a new
// version.
const SchemaVersion = 1

type jsonReport struct {
	SchemaVersion int           `json:"schemaVersion"`
	Tool          ToolJSON      `json:"tool"`
	Summary       jsonSummary   `json:"summary"`
	Findings      []FindingJSON `json:"findings"`
}

// ToolJSON identifies realmlint in JSON output.
type ToolJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type jsonSummary struct {
	Realms      int            `json:"realms"`
	Findings    int            `json:"findings"`
	Shown       int            `json:"shown"`
	Hidden      int            `json:"hidden"`
	MinSeverity check.Severity `json:"minSeverity"`
	BySeverity  map[string]int `json:"bySeverity"`
}

// FindingJSON is a finding in JSON output. The diff command uses it too.
type FindingJSON struct {
	Check    string         `json:"check"`
	Title    string         `json:"title"`
	Severity check.Severity `json:"severity"`
	Realm    string         `json:"realm"`
	Object   string         `json:"object,omitempty"`
	Message  string         `json:"message"`
	Why      string         `json:"why"`
	Fix      string         `json:"fix"`
	Source   string         `json:"source"`
}

// JSON writes the result as an indented JSON document.
func JSON(w io.Writer, res Result, version string) error {
	out := jsonReport{
		SchemaVersion: SchemaVersion,
		Tool:          ToolJSON{Name: "realmlint", Version: version},
		Summary: jsonSummary{
			Realms:      len(res.Realms),
			Findings:    res.Matched,
			Shown:       len(res.Findings),
			Hidden:      res.Hidden,
			MinSeverity: res.MinSeverity,
			BySeverity:  map[string]int{},
		},
		Findings: make([]FindingJSON, 0, len(res.Findings)),
	}
	for s := check.Low; s <= check.Critical; s++ {
		out.Summary.BySeverity[s.String()] = res.Counts[s]
	}
	for _, f := range res.Findings {
		out.Findings = append(out.Findings, NewFindingJSON(f))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// NewFindingJSON converts a finding for JSON output.
func NewFindingJSON(f check.Finding) FindingJSON {
	return FindingJSON{
		Check:    f.CheckID,
		Title:    f.Title,
		Severity: f.Severity,
		Realm:    f.Realm,
		Object:   f.Object,
		Message:  f.Message,
		Why:      f.Why,
		Fix:      f.Fix,
		Source:   f.Source,
	}
}
