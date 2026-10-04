// Package cli implements the realmlint command line.
package cli

import (
	"fmt"
	"io"

	"github.com/edzordzinam/realmlint/internal/version"
)

const usage = `realmlint checks Keycloak realm configuration.

Usage:
  realmlint <command> [arguments]

Commands:
  version    Print the realmlint version

Flags:
  -h, --help       Show this help
  -v, --version    Print the realmlint version
`

// Exit codes.
const (
	ExitOK    = 0
	ExitUsage = 2
)

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
	default:
		fmt.Fprintf(stderr, "realmlint: unknown command %q\nRun 'realmlint --help' for usage.\n", args[0])
		return ExitUsage
	}
}
