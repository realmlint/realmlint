# realmlint

Lint and diff Keycloak realm configuration.

realmlint reads realm exports and tells you what is risky, in plain English,
with the fix for each problem. It runs locally, makes no network calls and
collects no telemetry. Your exports never leave your machine.

```
$ realmlint check acme-realm.json
23 findings in 1 realm: 5 high, 11 medium, 7 low.

Realm acme (acme-realm.json)

  HIGH      Redirect URIs use wildcards [redirect-uri-wildcard]
            - client "web-spa": redirect URI "*" allows any destination
            Why: Keycloak sends authorization codes and tokens to the redirect
                 URI. A wildcard lets an attacker choose where they go. ...
            Fix: In the client's Settings, replace wildcard Valid redirect URIs
                 with the exact callback URLs.
...
```

It checks realm settings, token and session lifetimes, clients, admin access,
and expiring keys and certificates. See the [check catalog](docs/checks.md).

A hosted version that watches your instances continuously, records who
changed what, and produces access reviews is planned.
[Join the waitlist](https://realmlint.dev/?utm_source=github#hosted) to shape
it. Step-by-step [Keycloak fixes](https://realmlint.dev/fixes/index.html?utm_source=github)
are on the website.

## Install

Install script (Linux, macOS, Windows Git Bash; verifies the checksum):

```
curl -fsSL https://raw.githubusercontent.com/realmlint/realmlint/main/scripts/install.sh | bash
```

With Go:

```
go install github.com/realmlint/realmlint/cmd/realmlint@latest
```

With Docker:

```
docker run --rm -v "$PWD:/work" ghcr.io/realmlint/realmlint check acme-realm.json
```

Or download a binary from the [releases page](https://github.com/realmlint/realmlint/releases).

### Verify a download

Every release file and the container image carry a signed build provenance
attestation, made by the release workflow in this repository. With the
GitHub CLI:

```
gh attestation verify realmlint_1.0.0_linux_amd64.tar.gz --repo realmlint/realmlint
gh attestation verify oci://ghcr.io/realmlint/realmlint:1.0.0 --repo realmlint/realmlint
```

Each archive also has an SPDX SBOM (`<archive>.sbom.json`) listing what is
inside it, and `checksums.txt` covers the archives and the SBOMs.

## Get a realm export

realmlint works on the JSON that Keycloak exports.

- **Full export (recommended):** `kc.sh export --realm acme --file acme-realm.json`.
  This includes users, so the admin-access checks can run. Use
  `--dir exports/` instead of `--file` to get one file per realm; realmlint
  reads the directory and merges the separate users files.
- **Admin console:** Realm settings > Action > Partial export. This leaves out
  users, so checks about admin accounts have nothing to check.

Exports can contain secrets. realmlint never prints secret values, but treat
export files with care.

## Check a realm

```
realmlint check [flags] <file-or-directory>...
```

| Flag | Meaning |
|---|---|
| `--format text\|json\|sarif` | Output format. JSON for scripts, SARIF for code scanning. |
| `--min-severity LEVEL` | Report only findings at or above `low`, `medium`, `high` or `critical`. |
| `--fail-on LEVEL` | Exit 1 only for findings at or above `LEVEL`, or never with `none`. Defaults to `--min-severity`. |
| `--top N` | Show only the N most severe findings. |
| `--config FILE` | Ignore rules file. Defaults to `.realmlint.yaml` in the current directory. |

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` usage error
or unreadable input.

## See what changed

```
realmlint diff before.json after.json
```

Compares two exports and lists real configuration changes. Lists are matched
by client ID, username, alias or name, so reordering is not a change, and
internal IDs and timestamps are ignored. Secrets show only as changed. After
the changes, realmlint lists the findings that the change introduced or
resolved. Exit codes: `0` no changes, `1` changes, `2` error.

## Snapshot a live Keycloak (preview)

`realmlint-agent` reads realms from a running Keycloak through its admin API,
using a client with view-only permissions, and writes snapshots in the same
shape as `kc.sh export`, with secrets masked. The `realmlint` CLI itself still
makes no network calls; the agent connects only to your Keycloak.

```
go install github.com/realmlint/realmlint/cmd/realmlint-agent@latest

REALMLINT_CLIENT_SECRET=<secret> realmlint-agent \
  --keycloak-url https://sso.example.com --auth-realm myrealm --out snapshots/
realmlint check snapshots/
```

It also saves the realm's admin events to `snapshots/events/`, and with
`--interval 15m` it keeps running and refreshes the snapshots.

Create the agent's client in the realm you want to snapshot:

1. **Clients > Create client**: client ID `realmlint-agent`, turn on
   **Client authentication** and **Service account roles**, and turn off
   **Standard flow** and **Direct access grants**.
2. On its **Service account roles** tab, **Assign role**, filter by clients,
   and add these `realm-management` roles: `view-realm`, `view-clients`,
   `view-users`, `view-events`, `view-identity-providers`.
3. On **Client scopes > realmlint-agent-dedicated > Scope**, turn off
   **Full scope allowed** and assign the same five roles. Without this step
   every request fails with 403.
4. Copy the secret from the **Credentials** tab into `REALMLINT_CLIENT_SECRET`.

For the agent to report who changed what, turn on admin events in the realm
(**Realm settings > Events > Admin events settings**). Tested against Keycloak
26.6, 26.7 and 26.8.

## Ignore findings

Create `.realmlint.yaml`. Every entry needs a reason, so the next person knows
why.

```yaml
ignore:
  - check: full-scope-allowed
    reason: Our clients rely on role mappers and need every role.
  - check: redirect-uri-http
    realm: acme
    object: 'client "legacy-portal"'   # as printed in the output
    reason: Internal only, retired in Q1.
```

`realm` and `object` are optional. realmlint warns about entries that no longer
match anything.

## Use in CI

GitHub Actions, with findings in the Security tab. The action is on the
[GitHub Marketplace](https://github.com/marketplace/actions/realmlint):

```yaml
permissions:
  contents: read
  security-events: write
  actions: read   # needed by the code scanning upload in private repos

steps:
  - uses: actions/checkout@v7
  - uses: realmlint/realmlint@v1
    with:
      paths: keycloak/realms/*.json
      fail-on: high
```

| Input | Default | Meaning |
|---|---|---|
| `paths` | (required) | Files or directories, space separated; globs expand. |
| `version` | `latest` | realmlint version to install. Pin it for repeatable runs. |
| `min-severity` | `low` | Lowest severity to report. |
| `fail-on` | `min-severity` | Lowest severity that fails the job, or `none`. |
| `config` | `.realmlint.yaml` | Ignore rules file. |
| `sarif` | `true` | Upload findings to code scanning. Code scanning is free for public repos; private repos need GitHub code security enabled, otherwise set `false`. |
| `install` | `true` | Set `false` to use a `realmlint` already on `PATH`. |

Other CI systems: install the binary or use the Docker image, run
`realmlint check`, and use the exit code.

## Supported Keycloak versions

realmlint is tested against real exports from the latest three Keycloak 26.x
releases (currently 26.6, 26.7 and 26.8). Exports from older releases still
load, and realmlint suggests upgrading.

## Development

Requires Go 1.27+. Regenerating fixtures also requires Docker.

```
go test ./...                     # unit tests
golangci-lint run ./...           # lint (golangci-lint v2)
go run ./tools/gendocs            # regenerate docs/checks.md after changing checks
scripts/gen-fixtures.sh           # regenerate testdata/realms from real Keycloak releases
goreleaser release --snapshot --clean   # build release artifacts locally
```

Test fixtures in `testdata/realms` are real `kc.sh export` output from the
synthetic seed realm in `testdata/seed`, with secrets masked. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
