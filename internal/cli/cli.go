// Package cli implements the realmlint command line.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/realmlint/realmlint/internal/config"
	"github.com/realmlint/realmlint/internal/version"
	"github.com/realmlint/realmlint/pkg/check"
	"github.com/realmlint/realmlint/pkg/diff"
	"github.com/realmlint/realmlint/pkg/realm"
	"github.com/realmlint/realmlint/pkg/report"
	"github.com/realmlint/realmlint/pkg/terraform"
)

const usage = `realmlint checks Keycloak realm configuration.

Usage:
  realmlint <command> [arguments]

Commands:
  check      Check realm exports and report problems
  diff       Compare two realm exports and show what changed
  terraform  Check a Terraform plan, or export a realm to Terraform
  upgrade    List what upgrading Keycloak changes for your realms
  version    Print the realmlint version

Flags:
  -h, --help       Show this help
  -v, --version    Print the realmlint version

Run 'realmlint <command> --help' for details on a command.
`

const checkUsage = `Check Keycloak realm exports and report problems, most severe first.

Usage:
  realmlint check [flags] <file-or-directory>...

Accepts files and directories written by 'kc.sh export' or the admin
console's partial export. Separate users files in a directory are merged
into their realm.

Flags:
  --format text|json|sarif  Output format (default text). SARIF is for
                            GitHub code scanning and similar tools.
  --min-severity LEVEL      Report only findings at or above LEVEL:
                            low, medium, high or critical (default low)
  --fail-on LEVEL           Exit 1 only for findings at or above LEVEL, or
                            never with "none" (default: the --min-severity
                            level)
  --top N                   Show only the N most severe findings (default all)
  --config FILE             Read ignore rules from FILE (default
                            .realmlint.yaml in the current directory, if any)
  -h, --help                Show this help

Exit codes:
  0  no findings at or above --fail-on
  1  findings at or above --fail-on
  2  usage error or unreadable input

Ignore rules (.realmlint.yaml):
  ignore:
    - check: full-scope-allowed
      realm: acme                 # optional
      object: 'client "admin-ui"' # optional, as printed in the output
      reason: The admin UI needs every role the user has.
`

const terraformUsage = `Work with Keycloak managed by Terraform (keycloak/keycloak provider).

Usage:
  realmlint terraform check [flags] <plan.json>
  realmlint terraform export [--realm NAME] <file-or-directory>

check reads a saved plan in JSON and reports problems the plan would apply,
before terraform apply:

  terraform plan -out plan.out
  terraform show -json plan.out > plan.json
  realmlint terraform check --new-only plan.json

Only checks whose inputs Terraform declares run: realm security, token and
session settings, events, OpenID clients, identity providers and service
account admin roles. Findings name the resource that declares them.

check flags:
  --new-only                Report only findings the plan introduces, not
                            those already in the managed configuration
  --format text|json|sarif  Output format (default text)
  --min-severity LEVEL      Report only findings at or above LEVEL
  --fail-on LEVEL           Exit 1 only for findings at or above LEVEL, or never
                            with "none" (default: the --min-severity level)
  --top N                   Show only the N most severe findings
  --config FILE             Ignore rules (default .realmlint.yaml)

export writes Terraform configuration with import blocks for a realm export,
so a first terraform plan adopts the existing realm, clients, roles, groups
and identity providers. Secrets become variables; users, client scopes,
flows and role mappings are not exported.

Exit codes:
  0  no findings at or above --fail-on (check), or written (export)
  1  findings at or above --fail-on
  2  usage error or unreadable input
`

const diffUsage = `Compare two realm exports and show what changed.

Usage:
  realmlint diff [flags] <before> <after>

<before> and <after> are each a realm export file or directory. Realms are
matched by name. Lists are matched by clientId, username, alias or name, so
reordering is not a change. Internal IDs and timestamps are ignored, and
secret values are never shown. Findings that the change introduces or
resolves are listed after the changes.

Flags:
  --format text|json    Output format (default text)
  --config FILE         Ignore rules for the finding comparison (default
                        .realmlint.yaml in the current directory, if any)
  -h, --help            Show this help

Exit codes:
  0  no changes
  1  changes found
  2  usage error or unreadable input
`

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitUsage    = 2
)

// now is the time checks compare expiry dates against. Tests replace it.
var now = time.Now

// Run executes realmlint with args (without the program name) and returns
// the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}

	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return ExitOK
	case "-v", "--version", "version":
		fmt.Fprintf(stdout, "realmlint %s\n", version.String())
		return ExitOK
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "diff":
		return runDiff(args[1:], stdout, stderr)
	case "terraform":
		return runTerraform(args[1:], stdout, stderr)
	case "upgrade":
		return runUpgrade(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "realmlint: unknown command %q\nRun 'realmlint --help' for usage.\n", args[0])
		return ExitUsage
	}
}

// checkOpts are the flags shared by check and terraform check.
type checkOpts struct {
	format    string
	sev       check.Severity
	failSev   check.Severity
	failNever bool
	top       int
	cfg       *config.Config
}

// parseCheckFlags reads the shared check flags plus any extra ones. It
// returns the positional arguments, or an exit code when parsing ends the
// run (help or a usage error).
func parseCheckFlags(cmd, help string, args []string, extra func(*flag.FlagSet), stdout, stderr io.Writer) (checkOpts, []string, int, bool) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "text", "")
	minSeverity := fs.String("min-severity", "low", "")
	failOn := fs.String("fail-on", "", "")
	top := fs.Int("top", 0, "")
	configPath := fs.String("config", "", "")
	if extra != nil {
		extra(fs)
	}
	var o checkOpts
	paths, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, help)
		return o, nil, ExitOK, false
	}
	if err != nil {
		return o, nil, usageError(stderr, cmd, err.Error()), false
	}
	switch *format {
	case "text", "json", "sarif":
	default:
		return o, nil, usageError(stderr, cmd, fmt.Sprintf("unknown format %q (use text, json or sarif)", *format)), false
	}
	o.format = *format
	if o.sev, err = check.ParseSeverity(*minSeverity); err != nil {
		return o, nil, usageError(stderr, cmd, err.Error()), false
	}
	// By default a run fails on any finding it reports.
	o.failSev = o.sev
	switch *failOn {
	case "":
	case "none":
		o.failNever = true
	default:
		if o.failSev, err = check.ParseSeverity(*failOn); err != nil {
			return o, nil, usageError(stderr, cmd, "--fail-on: "+err.Error()+" or none"), false
		}
	}
	if *top < 0 {
		return o, nil, usageError(stderr, cmd, "--top must be 0 or more"), false
	}
	o.top = *top
	if o.cfg, err = config.Load(*configPath); err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return o, nil, ExitUsage, false
	}
	return o, paths, 0, true
}

// emit writes the report and returns the exit code for the findings.
func emit(o checkOpts, realms []*realm.Realm, findings []check.Finding, suppressed int, stdout, stderr io.Writer) int {
	res := report.Build(realms, findings, o.sev, o.top)
	res.Suppressed = suppressed
	var err error
	switch o.format {
	case "json":
		err = report.JSON(stdout, res, version.String())
	case "sarif":
		err = report.SARIF(stdout, res, version.String())
	default:
		report.Text(stdout, res)
	}
	if err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return ExitUsage
	}
	if o.failNever {
		return ExitOK
	}
	for _, f := range findings {
		if f.Severity >= o.failSev {
			return ExitFindings
		}
	}
	return ExitOK
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	o, paths, code, ok := parseCheckFlags("check", checkUsage, args, nil, stdout, stderr)
	if !ok {
		return code
	}
	if len(paths) == 0 {
		return usageError(stderr, "check", "no realm export files or directories given")
	}
	realms, err := realm.Load(paths...)
	if err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return ExitUsage
	}
	findings, suppressed := applyConfig(o.cfg, check.Run(realms, check.All(), now()), stderr)
	return emit(o, realms, findings, suppressed, stdout, stderr)
}

// applyConfig removes suppressed findings and warns about ignore entries
// that matched nothing.
func applyConfig(cfg *config.Config, findings []check.Finding, stderr io.Writer) ([]check.Finding, int) {
	kept, suppressed, unused := cfg.Apply(findings)
	for _, ig := range unused {
		where := ig.Check
		if ig.Realm != "" {
			where += " in realm " + ig.Realm
		}
		if ig.Object != "" {
			where += " on " + ig.Object
		}
		fmt.Fprintf(stderr, "realmlint: warning: %s: ignore entry for %s matched no findings\n", cfg.Path, where)
	}
	return kept, suppressed
}

func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "text", "")
	configPath := fs.String("config", "", "")

	paths, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, diffUsage)
		return ExitOK
	}
	if err != nil {
		return usageError(stderr, "diff", err.Error())
	}
	if *format != "text" && *format != "json" {
		return usageError(stderr, "diff", fmt.Sprintf("unknown format %q (use text or json)", *format))
	}
	if len(paths) != 2 {
		return usageError(stderr, "diff", fmt.Sprintf("need exactly two exports, <before> and <after>; got %d", len(paths)))
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return ExitUsage
	}
	before, err := realm.Load(paths[0])
	if err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return ExitUsage
	}
	after, err := realm.Load(paths[1])
	if err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return ExitUsage
	}

	t := now()
	// Unused-entry warnings are left to the check command; in a diff an
	// entry often matches only one side.
	beforeFindings, _, _ := cfg.Apply(check.Run(before, check.All(), t))
	afterFindings, _, _ := cfg.Apply(check.Run(after, check.All(), t))
	added, resolved := diff.CompareFindings(beforeFindings, afterFindings)
	res := diff.Result{
		Changes:          diff.Compare(before, after),
		NewFindings:      report.Build(after, added, check.Low, 0).Findings,
		ResolvedFindings: report.Build(before, resolved, check.Low, 0).Findings,
	}
	if *format == "json" {
		if err := diff.JSON(stdout, res, version.String()); err != nil {
			fmt.Fprintf(stderr, "realmlint: %v\n", err)
			return ExitUsage
		}
	} else {
		diff.Text(stdout, res)
	}

	if len(res.Changes) > 0 {
		return ExitFindings
	}
	return ExitOK
}

// parseInterspersed parses flags that appear before, between or after
// positional arguments, which the flag package alone does not allow.
// Everything after "--" is positional.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var afterDashes []string
	for i, a := range args {
		if a == "--" {
			afterDashes = args[i+1:]
			args = args[:i]
			break
		}
	}
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return append(positional, afterDashes...), nil
}

func usageError(stderr io.Writer, command, msg string) int {
	fmt.Fprintf(stderr, "realmlint %s: %s\nRun 'realmlint %s --help' for usage.\n", command, msg, command)
	return ExitUsage
}

func runTerraform(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, terraformUsage)
		return ExitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, terraformUsage)
		return ExitOK
	case "check":
		return runTerraformCheck(args[1:], stdout, stderr)
	case "export":
		return runTerraformExport(args[1:], stdout, stderr)
	default:
		return usageError(stderr, "terraform", fmt.Sprintf("unknown subcommand %q (use check or export)", args[0]))
	}
}

func runTerraformCheck(args []string, stdout, stderr io.Writer) int {
	var newOnly *bool
	o, paths, code, ok := parseCheckFlags("terraform check", terraformUsage, args, func(fs *flag.FlagSet) {
		newOnly = fs.Bool("new-only", false, "")
	}, stdout, stderr)
	if !ok {
		return code
	}
	if len(paths) != 1 {
		return usageError(stderr, "terraform check", "give one plan file (terraform show -json plan.out > plan.json)")
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return ExitUsage
	}
	plan, err := terraform.ParsePlan(data, paths[0])
	if err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return ExitUsage
	}
	for _, addr := range plan.Unresolved {
		fmt.Fprintf(stderr, "realmlint: warning: could not tell which realm %s belongs to; it was not checked\n", addr)
	}
	t := now()
	findings := check.Run(plan.After, terraform.Checks(), t)
	if *newOnly {
		findings = terraform.NewFindings(findings, check.Run(plan.Before, terraform.Checks(), t))
	}
	findings, suppressed := applyConfig(o.cfg, findings, stderr)
	// Name the resource that declares each finding.
	for i := range findings {
		if addr := plan.AddressFor(findings[i].Realm, findings[i].Object, findings[i].CheckID); addr != "" {
			findings[i].Message += " (" + addr + ")"
		}
	}
	return emit(o, plan.After, findings, suppressed, stdout, stderr)
}

func runTerraformExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("terraform export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	only := fs.String("realm", "", "")
	paths, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, terraformUsage)
		return ExitOK
	}
	if err != nil {
		return usageError(stderr, "terraform export", err.Error())
	}
	if len(paths) == 0 {
		return usageError(stderr, "terraform export", "no realm export files or directories given")
	}
	realms, err := realm.Load(paths...)
	if err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return ExitUsage
	}
	if *only != "" {
		var kept []*realm.Realm
		for _, r := range realms {
			if r.Realm == *only {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			return usageError(stderr, "terraform export", fmt.Sprintf("realm %q is not in the export", *only))
		}
		realms = kept
	}
	if err := terraform.Export(stdout, realms); err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return ExitUsage
	}
	return ExitOK
}
