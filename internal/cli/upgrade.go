package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/realmlint/realmlint/pkg/realm"
	"github.com/realmlint/realmlint/pkg/upgrade"
)

const upgradeUsage = `List what upgrading Keycloak changes, from Keycloak's upgrading guide, and
which of those changes touch your realms.

Usage:
  realmlint upgrade [flags] <file-or-directory>...

The version you run comes from the exports' keycloakVersion, or --from.
Every change the guide lists between that version and --to is shown with a
link to the guide. realmlint checks the realms for the changes realm
configuration shows (for example wildcard hostnames in redirect URIs,
deprecated client switches, Twitter identity providers) and names the
objects they affect. The rest (server options, APIs, themes) you read.

Upgrades from any 26.x release are covered.

Flags:
  --from VERSION        The Keycloak version you run (default: from the exports)
  --to VERSION          The version you upgrade to (default: the newest the
                        guide lists, currently %s)
  --all                 Also list deprecations, changes checked with no impact
                        and other notable changes
  --format text|json    Output format (default text)
  -h, --help            Show this help

Exit codes:
  0  no checked change touches the realms
  1  a change touches the realms
  2  usage error or unreadable input
`

func runUpgrade(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	from := fs.String("from", "", "")
	to := fs.String("to", upgrade.Versions()[0], "")
	all := fs.Bool("all", false, "")
	format := fs.String("format", "text", "")

	paths, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprintf(stdout, upgradeUsage, upgrade.Versions()[0])
		return ExitOK
	}
	if err != nil {
		return usageError(stderr, "upgrade", err.Error())
	}
	if *format != "text" && *format != "json" {
		return usageError(stderr, "upgrade", fmt.Sprintf("unknown format %q (use text or json)", *format))
	}
	if len(paths) == 0 {
		return usageError(stderr, "upgrade", "no realm export files or directories given")
	}
	realms, err := realm.Load(paths...)
	if err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return ExitUsage
	}
	if *from == "" {
		*from = oldestVersion(realms)
		if *from == "" {
			return usageError(stderr, "upgrade", "the exports do not record the Keycloak version; pass --from")
		}
	}
	docs := make(map[string]map[string]any, len(realms))
	for _, r := range realms {
		docs[r.Realm] = r.Raw
	}
	rep, err := upgrade.Advise(*from, *to, docs)
	if err != nil {
		return usageError(stderr, "upgrade", err.Error())
	}

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			Guide string `json:"guide"`
			upgrade.Report
		}{upgrade.GuideURL, rep}); err != nil {
			fmt.Fprintf(stderr, "realmlint: %v\n", err)
			return ExitUsage
		}
	} else {
		writeUpgrade(stdout, rep, *all)
	}
	for _, it := range rep.Items {
		if it.Status == upgrade.Affected {
			return ExitFindings
		}
	}
	return ExitOK
}

// oldestVersion returns the oldest keycloakVersion among the realms, since
// the server is upgraded from the version it runs.
func oldestVersion(realms []*realm.Realm) string {
	oldest := ""
	for _, r := range realms {
		if _, ok := upgrade.Parse(r.KeycloakVersion); !ok {
			continue
		}
		if oldest == "" || upgrade.Compare(r.KeycloakVersion, oldest) < 0 {
			oldest = r.KeycloakVersion
		}
	}
	return oldest
}

func writeUpgrade(w io.Writer, rep upgrade.Report, all bool) {
	var affected, read, deprecated, noImpact, other []upgrade.Advice
	for _, it := range rep.Items {
		switch {
		case it.Status == upgrade.Affected:
			affected = append(affected, it)
		case it.Status == upgrade.Clear:
			noImpact = append(noImpact, it)
		case it.Category == "breaking" || it.Category == "removed":
			read = append(read, it)
		case it.Category == "deprecated":
			deprecated = append(deprecated, it)
		default:
			other = append(other, it)
		}
	}
	fmt.Fprintf(w, "Upgrading Keycloak %s to %s: %d changes in Keycloak's upgrading guide.\n", rep.From, rep.To, len(rep.Items))
	if upgrade.Compare(rep.From, upgrade.Oldest) < 0 {
		fmt.Fprintf(w, "The list starts at %s; for older versions read the guide's earlier sections too.\n", upgrade.Oldest)
	}
	if len(rep.Items) == 0 {
		return
	}

	fmt.Fprintf(w, "\nAffects your realms (%d)\n", len(affected))
	if len(affected) == 0 {
		fmt.Fprintln(w, "\n  No checked change touches these realms. Still read the breaking changes.")
	}
	for _, it := range affected {
		fmt.Fprintf(w, "\n  %s  [%s, %s]\n", it.Title, it.Category, it.Version)
		for _, h := range it.Hits {
			fmt.Fprintf(w, "    %s  %s: %s\n", h.Realm, h.Object, h.Detail)
		}
		fmt.Fprintf(w, "    %s\n", it.URL)
	}

	list := func(title string, items []upgrade.Advice) {
		fmt.Fprintf(w, "\n%s (%d)\n\n", title, len(items))
		for _, it := range items {
			fmt.Fprintf(w, "  %-8s %s\n           %s\n", it.Version, it.Title, it.URL)
		}
	}
	if len(read) > 0 {
		list("Breaking or removed, read before upgrading", read)
	}
	if all {
		list("Deprecated", deprecated)
		list("Checked, no impact", noImpact)
		list("Other notable changes", other)
		return
	}
	var more []string
	for _, m := range []struct {
		n    int
		what string
	}{{len(deprecated), "deprecated"}, {len(noImpact), "checked with no impact"}, {len(other), "other notable changes"}} {
		if m.n > 0 {
			more = append(more, fmt.Sprintf("%d %s", m.n, m.what))
		}
	}
	if len(more) > 0 {
		fmt.Fprintf(w, "\nNot listed: %s. Add --all to list them.\n", strings.Join(more, ", "))
	}
}
