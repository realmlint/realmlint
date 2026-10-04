// Package cli implements the realmlint command line.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/edzordzinam/realmlint/internal/check"
	"github.com/edzordzinam/realmlint/internal/realm"
	"github.com/edzordzinam/realmlint/internal/report"
	"github.com/edzordzinam/realmlint/internal/version"
)

const usage = `realmlint checks Keycloak realm configuration.

Usage:
  realmlint <command> [arguments]

Commands:
  check      Check realm exports and report problems
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
  --format text|json      Output format (default text)
  --min-severity LEVEL    Report only findings at or above LEVEL:
                          low, medium, high or critical (default low)
  --top N                 Show only the N most severe findings (default all)
  -h, --help              Show this help

Exit codes:
  0  no findings at or above --min-severity
  1  findings reported
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
	default:
		fmt.Fprintf(stderr, "realmlint: unknown command %q\nRun 'realmlint --help' for usage.\n", args[0])
		return ExitUsage
	}
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "text", "")
	minSeverity := fs.String("min-severity", "low", "")
	top := fs.Int("top", 0, "")

	paths, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, checkUsage)
		return ExitOK
	}
	if err != nil {
		return usageError(stderr, "check", err.Error())
	}
	if *format != "text" && *format != "json" {
		return usageError(stderr, "check", fmt.Sprintf("unknown format %q (use text or json)", *format))
	}
	sev, err := check.ParseSeverity(*minSeverity)
	if err != nil {
		return usageError(stderr, "check", err.Error())
	}
	if *top < 0 {
		return usageError(stderr, "check", "--top must be 0 or more")
	}
	if len(paths) == 0 {
		return usageError(stderr, "check", "no realm export files or directories given")
	}

	realms, err := realm.Load(paths...)
	if err != nil {
		fmt.Fprintf(stderr, "realmlint: %v\n", err)
		return ExitUsage
	}

	res := report.Build(realms, check.Run(realms, check.All(), now()), sev, *top)
	if *format == "json" {
		if err := report.JSON(stdout, res, version.String()); err != nil {
			fmt.Fprintf(stderr, "realmlint: %v\n", err)
			return ExitUsage
		}
	} else {
		report.Text(stdout, res)
	}

	if res.Matched > 0 {
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
