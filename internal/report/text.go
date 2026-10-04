package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/edzordzinam/realmlint/internal/check"
)

const (
	lineWidth = 80
	// Findings are indented under a severity column: two spaces, the
	// widest label ("CRITICAL"), two spaces.
	labelWidth = 8
	indent     = 2 + labelWidth + 2
)

// Text writes the result for a terminal: a summary line, then findings
// grouped by realm. Findings of the same check and severity share one
// heading and one explanation.
func Text(w io.Writer, res Result) {
	fmt.Fprintln(w, summary(res))

	for _, r := range res.Realms {
		var findings []check.Finding
		for _, f := range res.Findings {
			if f.Realm == r.Realm {
				findings = append(findings, f)
			}
		}
		if len(findings) == 0 {
			continue
		}

		fmt.Fprintln(w)
		fmt.Fprintf(w, "Realm %s (%s)\n", r.Realm, r.Source)
		for i := 0; i < len(findings); {
			j := i + 1
			for j < len(findings) && findings[j].CheckID == findings[i].CheckID && findings[j].Severity == findings[i].Severity {
				j++
			}
			writeGroup(w, findings[i:j])
			i = j
		}
	}
}

func writeGroup(w io.Writer, group []check.Finding) {
	first := group[0]
	pad := strings.Repeat(" ", indent)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %-*s  %s [%s]\n", labelWidth, strings.ToUpper(first.Severity.String()), first.Title, first.CheckID)
	for _, f := range group {
		line := f.Message
		if f.Object != "" {
			line = f.Object + ": " + f.Message
		}
		writeWrapped(w, pad+"- ", pad+"  ", line)
	}
	writeWrapped(w, pad+"Why: ", pad+"     ", first.Why)
	writeWrapped(w, pad+"Fix: ", pad+"     ", first.Fix)
}

func summary(res Result) string {
	realms := plural(len(res.Realms), "realm")
	var b strings.Builder
	if res.Matched == 0 {
		fmt.Fprintf(&b, "No findings in %s.", realms)
	} else {
		var parts []string
		for s := check.Critical; s >= check.Low; s-- {
			if n := res.Counts[s]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, s))
			}
		}
		fmt.Fprintf(&b, "%s in %s: %s.", plural(res.Matched, "finding"), realms, strings.Join(parts, ", "))
		if len(res.Findings) < res.Matched {
			fmt.Fprintf(&b, " Showing the top %d.", len(res.Findings))
		}
	}
	if res.Hidden > 0 {
		fmt.Fprintf(&b, " %s below %s not shown.", plural(res.Hidden, "finding"), res.MinSeverity)
	}
	return b.String()
}

// writeWrapped writes text wrapped to lineWidth, starting with first and
// continuing with rest.
func writeWrapped(w io.Writer, first, rest, text string) {
	prefix := first
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && len(prefix)+len(line)+1+len(word) > lineWidth {
			fmt.Fprintln(w, prefix+line)
			prefix, line = rest, ""
		}
		if line == "" {
			line = word
		} else {
			line += " " + word
		}
	}
	fmt.Fprintln(w, prefix+line)
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
