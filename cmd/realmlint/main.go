// Command realmlint checks Keycloak realm configuration.
package main

import (
	"os"

	"github.com/edzordzinam/realmlint/internal/cli"
	rlversion "github.com/edzordzinam/realmlint/internal/version"
)

// version is set by release builds: -ldflags "-X main.version=1.0.0".
var version string

func main() {
	if version != "" {
		rlversion.Version = version
	}
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
