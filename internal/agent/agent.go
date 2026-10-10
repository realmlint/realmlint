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
  realmlint-agent --keycloak-url URL (--out DIR | --push-url URL) [flags]

With --out, writes each realm to DIR/<realm>.json in the shape of
'kc.sh export', with secrets masked, and its admin events to
DIR/events/<realm>.json. Check the result with 'realmlint check DIR'.
With --push-url, sends the same data to hosted realmlint.

The agent logs in as a confidential client with a service account. Give the
service account these roles: view-realm, view-clients, view-users,
view-events and view-identity-providers, from realm-management when the
client is in the realm it reads, or from each realm's <realm>-realm client
when it is in master. If the client has full scope turned off, add the same
roles to its scope mappings.

Flags:
  --keycloak-url URL     Keycloak base URL, for example https://sso.example.com
                         (or REALMLINT_KEYCLOAK_URL)
  --auth-realm NAME      Realm the agent's client lives in (default master)
  --realm NAME           Realm to snapshot; repeat or comma-separate for more
                         (default: every realm the client can see)
  --out DIR              Directory to write snapshots to
  --push-url URL         Hosted realmlint ingest URL (https; http only for
                         localhost)
  --interval DURATION    Repeat every DURATION, for example 15m (default: run once)
  --events-since DURATION
                         On the first run, fetch admin events this far back
                         (default 24h); later runs continue from the last run
  --backup-to TARGET     Also write each realm's export (secrets masked) to
                         your own storage: a directory or s3://bucket/prefix,
                         using this environment's AWS credentials (or
                         REALMLINT_BACKUP_TO). With --push-url, only while
                         backups are on for the instance in realmlint.
  --backup-every DURATION
                         How often to back up (default 24h)
  -h, --help             Show this help
  -v, --version          Print the version

Environment:
  REALMLINT_CLIENT_ID      Client ID (default realmlint-agent)
  REALMLINT_CLIENT_SECRET  Client secret (required)
  REALMLINT_AGENT_TOKEN    Agent token for --push-url
  REALMLINT_BACKUP_S3_ENDPOINT
                           An S3-compatible endpoint (MinIO, Ceph, ...) for
                           --backup-to s3://...
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
	PushURL      string
	AgentToken   string
	Interval     time.Duration
	EventsSince  time.Duration
	BackupTo     string
	BackupEvery  time.Duration
	BackupS3URL  string // S3-compatible endpoint
}

// Run parses args and runs the agent until ctx is cancelled (with an
// interval) or after one pass (without one).
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, code := parse(args, stdout, stderr)
	if code >= 0 {
		return code
	}
	client := keycloak.NewClient(cfg.KeycloakURL, cfg.AuthRealm, cfg.ClientID, cfg.ClientSecret)
	var push *pusher
	if cfg.PushURL != "" {
		push = newPusher(cfg.PushURL, cfg.AgentToken)
	}

	var store backupStore
	if cfg.BackupTo != "" {
		var err error
		if store, err = newBackupStore(ctx, cfg.BackupTo, cfg.BackupS3URL); err != nil {
			fmt.Fprintf(stderr, "realmlint-agent: %v\n", err)
			return ExitUsage
		}
	}

	since := time.Now().Add(-cfg.EventsSince)
	var lastBackup time.Time
	for {
		started := time.Now()
		snapshots, err := runOnce(ctx, client, push, cfg, since, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "realmlint-agent: %v\n", err)
		} else {
			since = started
		}
		if len(snapshots) > 0 && started.Sub(lastBackup) >= cfg.BackupEvery && (store != nil || push != nil) {
			if maybeBackup(ctx, store, push, snapshots, started, stderr) {
				lastBackup = started
			}
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
	fs.StringVar(&cfg.PushURL, "push-url", "", "")
	fs.DurationVar(&cfg.Interval, "interval", 0, "")
	fs.DurationVar(&cfg.EventsSince, "events-since", 24*time.Hour, "")
	fs.StringVar(&cfg.BackupTo, "backup-to", os.Getenv("REALMLINT_BACKUP_TO"), "")
	fs.DurationVar(&cfg.BackupEvery, "backup-every", 24*time.Hour, "")
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
	cfg.AgentToken = os.Getenv("REALMLINT_AGENT_TOKEN")
	cfg.BackupS3URL = os.Getenv("REALMLINT_BACKUP_S3_ENDPOINT")

	switch {
	case cfg.KeycloakURL == "":
		return cfg, usageError(stderr, "--keycloak-url (or REALMLINT_KEYCLOAK_URL) is required")
	case !strings.HasPrefix(cfg.KeycloakURL, "https://") && !strings.HasPrefix(cfg.KeycloakURL, "http://"):
		return cfg, usageError(stderr, "--keycloak-url must start with https:// or http://")
	case cfg.Out == "" && cfg.PushURL == "":
		return cfg, usageError(stderr, "give --out, --push-url or both")
	case cfg.ClientSecret == "":
		return cfg, usageError(stderr, "set REALMLINT_CLIENT_SECRET to the agent client's secret")
	case cfg.Interval < 0 || (cfg.Interval > 0 && cfg.Interval < time.Minute):
		return cfg, usageError(stderr, "--interval must be at least 1m")
	case cfg.EventsSince <= 0:
		return cfg, usageError(stderr, "--events-since must be positive")
	case cfg.BackupEvery < time.Hour:
		return cfg, usageError(stderr, "--backup-every must be at least 1h")
	}
	if cfg.PushURL != "" {
		if err := validatePushURL(cfg.PushURL); err != nil {
			return cfg, usageError(stderr, err.Error())
		}
		if cfg.AgentToken == "" {
			return cfg, usageError(stderr, "set REALMLINT_AGENT_TOKEN to push to hosted realmlint")
		}
	}
	return cfg, -1
}

// maybeBackup writes the snapshots to the backup target when backups are
// on, and tells realmlint how it went. With --push-url, realmlint decides
// whether backups are on (the instance's setting and plan). It reports
// whether this was a backup attempt, successful or not.
func maybeBackup(ctx context.Context, store backupStore, push *pusher, snapshots map[string]map[string]any, at time.Time, stderr io.Writer) bool {
	if push != nil {
		on, err := push.backupsOn(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "realmlint-agent: backup settings: %v\n", err)
			return false
		}
		if !on {
			if store != nil {
				fmt.Fprintln(stderr, "backup: off for this instance in realmlint (instance settings); not writing")
			}
			return false
		}
		if store == nil {
			push.backupStatus(ctx, backupReport{At: at, Error: "Backups are on in realmlint, but this agent has no --backup-to target."})
			return true
		}
	}
	err := backup(ctx, store, snapshots, at)
	report := backupReport{At: at, Target: store.where(), Realms: len(snapshots)}
	if err != nil {
		report.Error = err.Error()
		fmt.Fprintf(stderr, "backup to %s failed: %v\n", store.where(), err)
	} else {
		fmt.Fprintf(stderr, "backup: %d realms written to %s\n", len(snapshots), store.where())
	}
	if push != nil {
		push.backupStatus(ctx, report)
	}
	return true
}

// runOnce snapshots every requested realm and writes the files. It carries
// on past a failing realm and reports all failures at the end. It returns
// the snapshots taken, for backups.
func runOnce(ctx context.Context, client *keycloak.Client, push *pusher, cfg Config, since time.Time, stderr io.Writer) (map[string]map[string]any, error) {
	taken := map[string]map[string]any{}
	realms := cfg.Realms
	if len(realms) == 0 {
		var err error
		if realms, err = client.Realms(ctx); err != nil {
			return nil, err
		}
		if len(realms) == 0 {
			return nil, errors.New("the agent's client cannot see any realms; check its roles")
		}
	}
	version := client.Version(ctx)

	var failed []string
	for _, name := range realms {
		start := time.Now()
		snapshot, err := client.Snapshot(ctx, name, version)
		var events []any
		eventsNote := ""
		if err == nil {
			events, err = client.AdminEvents(ctx, name, since)
			// Admin events only name who made a change: without them the
			// snapshot is still worth sending.
			if errors.Is(err, keycloak.ErrEventsForbidden) {
				err = nil
				eventsNote = ", admin events not readable: " + eventsRoleHint(cfg.AuthRealm, name)
			}
		}
		if err == nil && cfg.Out != "" {
			err = writeJSON(filepath.Join(cfg.Out, safeName(name)+".json"), snapshot)
			if err == nil {
				err = writeJSON(filepath.Join(cfg.Out, "events", safeName(name)+".json"), events)
			}
		}
		// Events go first, so the service can attribute the changes it finds
		// in the snapshot.
		if err == nil && push != nil {
			err = push.events(ctx, name, events)
			if err == nil {
				err = push.snapshot(ctx, name, start, snapshot)
			}
		}
		if err != nil {
			fmt.Fprintf(stderr, "realm %s: %v\n", name, err)
			failed = append(failed, name)
			continue
		}
		taken[name] = snapshot
		fmt.Fprintf(stderr, "realm %s: snapshot taken, %d admin events, %s%s\n", name, len(events), time.Since(start).Round(time.Millisecond), eventsNote)
	}
	if len(failed) > 0 {
		return taken, fmt.Errorf("%d of %d realms failed: %s", len(failed), len(realms), strings.Join(failed, ", "))
	}
	return taken, nil
}

// eventsRoleHint says where the missing view-events role comes from: for a
// client in the master realm reading another realm, from that realm's
// "<realm>-realm" client in master; otherwise from realm-management.
func eventsRoleHint(authRealm, realmName string) string {
	if authRealm == "master" {
		return fmt.Sprintf("give the agent's service account the view-events role of client %s-realm (in the master realm); changes show no author until then", realmName)
	}
	return "give the agent's service account the view-events role of client realm-management; changes show no author until then"
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
