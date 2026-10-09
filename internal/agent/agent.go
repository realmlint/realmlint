// Package agent implements realmlint-agent: it snapshots realms from a live
// Keycloak through the admin API and writes them, with secrets masked, in
// the same shape as `kc.sh export`.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/realmlint/realmlint/internal/version"
	"github.com/realmlint/realmlint/pkg/keycloak"
)

const usage = `realmlint-agent snapshots Keycloak realms through the admin API.

Usage:
  realmlint-agent --keycloak-url URL --out DIR [flags]

Writes each realm to DIR/<realm>.json in the shape of 'kc.sh export', with
secrets masked, and its admin events to DIR/events/<realm>.json. Check the
result with 'realmlint check DIR'.

The agent logs in as a confidential client with a service account. Give the
service account these realm-management roles: view-realm, view-clients,
view-users, view-events and view-identity-providers. If the client has full
scope turned off, add the same roles to its scope mappings.

Flags:
  --keycloak-url URL     Keycloak base URL, for example https://sso.example.com
                         (or REALMLINT_KEYCLOAK_URL)
  --auth-realm NAME      Realm the agent's client lives in (default master)
  --realm NAME           Realm to snapshot; repeat or comma-separate for more
                         (default: every realm the client can see)
  --out DIR              Directory to write snapshots to
  --interval DURATION    Repeat every DURATION, for example 15m (default: run once)
  --events-since DURATION
                         On the first run, fetch admin events this far back
                         (default 24h); later runs continue from the last run
  -h, --help             Show this help
  -v, --version          Print the version

Environment:
  REALMLINT_CLIENT_ID      Client ID (default realmlint-agent)
  REALMLINT_CLIENT_SECRET  Client secret (required)
`

// Exit codes.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

// Config is the agent's configuration.
type Config struct {
	KeycloakURL  string
	AuthRealm    string
	ClientID     string
	ClientSecret string
	Realms       []string
	Out          string
	Interval     time.Duration
	EventsSince  time.Duration
}

// Run parses args and runs the agent until ctx is cancelled (with an
// interval) or after one pass (without one).
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, code := parse(args, stdout, stderr)
	if code >= 0 {
		return code
	}
	client := keycloak.NewClient(cfg.KeycloakURL, cfg.AuthRealm, cfg.ClientID, cfg.ClientSecret)

	since := time.Now().Add(-cfg.EventsSince)
	for {
		started := time.Now()
		err := runOnce(ctx, client, cfg, since, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "realmlint-agent: %v\n", err)
		} else {
			since = started
		}
		if cfg.Interval == 0 {
			if err != nil {
				return ExitError
			}
			return ExitOK
		}
		select {
		case <-ctx.Done():
			return ExitOK
		case <-time.After(cfg.Interval):
		}
	}
}

func parse(args []string, stdout, stderr io.Writer) (Config, int) {
	fs := flag.NewFlagSet("realmlint-agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := Config{}
	var realms string
	var showVersion bool
	fs.StringVar(&cfg.KeycloakURL, "keycloak-url", os.Getenv("REALMLINT_KEYCLOAK_URL"), "")
	fs.StringVar(&cfg.AuthRealm, "auth-realm", "master", "")
	fs.Func("realm", "", func(v string) error {
		realms += "," + v
		return nil
	})
	fs.StringVar(&cfg.Out, "out", "", "")
	fs.DurationVar(&cfg.Interval, "interval", 0, "")
	fs.DurationVar(&cfg.EventsSince, "events-since", 24*time.Hour, "")
	fs.BoolVar(&showVersion, "version", false, "")
	fs.BoolVar(&showVersion, "v", false, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return cfg, ExitOK
		}
		return cfg, usageError(stderr, err.Error())
	}
	if showVersion {
		fmt.Fprintf(stdout, "realmlint-agent %s\n", version.String())
		return cfg, ExitOK
	}
	if fs.NArg() > 0 {
		return cfg, usageError(stderr, fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}
	for _, r := range strings.Split(realms, ",") {
		if r = strings.TrimSpace(r); r != "" {
			cfg.Realms = append(cfg.Realms, r)
		}
	}
	cfg.ClientID = os.Getenv("REALMLINT_CLIENT_ID")
	if cfg.ClientID == "" {
		cfg.ClientID = "realmlint-agent"
	}
	cfg.ClientSecret = os.Getenv("REALMLINT_CLIENT_SECRET")

	switch {
	case cfg.KeycloakURL == "":
		return cfg, usageError(stderr, "--keycloak-url (or REALMLINT_KEYCLOAK_URL) is required")
	case !strings.HasPrefix(cfg.KeycloakURL, "https://") && !strings.HasPrefix(cfg.KeycloakURL, "http://"):
		return cfg, usageError(stderr, "--keycloak-url must start with https:// or http://")
	case cfg.Out == "":
		return cfg, usageError(stderr, "--out is required")
	case cfg.ClientSecret == "":
		return cfg, usageError(stderr, "set REALMLINT_CLIENT_SECRET to the agent client's secret")
	case cfg.Interval < 0 || (cfg.Interval > 0 && cfg.Interval < time.Minute):
		return cfg, usageError(stderr, "--interval must be at least 1m")
	case cfg.EventsSince <= 0:
		return cfg, usageError(stderr, "--events-since must be positive")
	}
	return cfg, -1
}

// runOnce snapshots every requested realm and writes the files. It carries
// on past a failing realm and reports all failures at the end.
func runOnce(ctx context.Context, client *keycloak.Client, cfg Config, since time.Time, stderr io.Writer) error {
	realms := cfg.Realms
	if len(realms) == 0 {
		var err error
		if realms, err = client.Realms(ctx); err != nil {
			return err
		}
		if len(realms) == 0 {
			return errors.New("the agent's client cannot see any realms; check its roles")
		}
	}
	version := client.Version(ctx)

	var failed []string
	for _, name := range realms {
		start := time.Now()
		snapshot, err := client.Snapshot(ctx, name, version)
		if err == nil {
			err = writeJSON(filepath.Join(cfg.Out, safeName(name)+".json"), snapshot)
		}
		var events []any
		if err == nil {
			events, err = client.AdminEvents(ctx, name, since)
		}
		if err == nil {
			err = writeJSON(filepath.Join(cfg.Out, "events", safeName(name)+".json"), events)
		}
		if err != nil {
			fmt.Fprintf(stderr, "realm %s: %v\n", name, err)
			failed = append(failed, name)
			continue
		}
		fmt.Fprintf(stderr, "realm %s: snapshot written, %d admin events, %s\n", name, len(events), time.Since(start).Round(time.Millisecond))
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d realms failed: %s", len(failed), len(realms), strings.Join(failed, ", "))
	}
	return nil
}

// writeJSON writes v to path atomically, so readers never see a partial
// file.
func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// safeName keeps realm names usable as file names.
func safeName(name string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == 0 {
			return '_'
		}
		return r
	}, name)
}

func usageError(stderr io.Writer, msg string) int {
	fmt.Fprintf(stderr, "realmlint-agent: %s\nRun 'realmlint-agent --help' for usage.\n", msg)
	return ExitUsage
}
