// Command realmlint checks Keycloak realm configuration.
package main

import (
	"os"

	"github.com/edzordzinam/realmlint/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
