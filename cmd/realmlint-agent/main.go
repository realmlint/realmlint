// Command realmlint-agent snapshots Keycloak realms through the admin API.
// Unlike the realmlint CLI, it makes network calls: to the Keycloak it reads.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/realmlint/realmlint/internal/agent"
	rlversion "github.com/realmlint/realmlint/internal/version"
)

// version is set by release builds: -ldflags "-X main.version=1.0.0".
var version string

func main() {
	if version != "" {
		rlversion.Version = version
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := agent.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
