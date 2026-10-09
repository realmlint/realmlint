# Contributing

Thanks for helping. Bug reports, new checks and fixes to existing checks are
all welcome.

## Reporting a wrong finding

Open an issue with the check ID, the realmlint version, the Keycloak version,
and the relevant part of the export. Remove secrets and real names first.

## Setup

You need Go 1.27 or later. Docker is only needed to regenerate fixtures.

```
go test ./...
golangci-lint run ./...
```

## Adding or changing a check

1. Add the check to the right file in `pkg/check` (realm, token, client,
   access or expiry checks). Give it a stable kebab-case ID; users reference
   IDs in their ignore files, so never rename one.
2. Write `Title`, `Why` and `Fix` for someone who is not a Keycloak expert.
   `Fix` should name the place in the admin console.
3. Add positive and negative cases to `TestChecks` in
   `pkg/check/check_test.go`. The clean realm in that file must keep
   producing no findings.
4. If the seed realm triggers the new check, update `seedFindings` in
   `pkg/check/fixture_test.go` and the golden file with
   `go test ./internal/cli -update`.
5. Regenerate the catalog: `go run ./tools/gendocs`.

Keep checks quiet on Keycloak's defaults for its built-in clients; noise makes
people stop reading.

## Fixtures

`testdata/realms` holds real exports from each supported Keycloak release,
generated from `testdata/seed/acme-realm.json`. To add a Keycloak release,
update `VERSIONS` in `scripts/gen-fixtures.sh` and `OldestSupportedVersion` in
`pkg/check/expiry_checks.go`, then run `scripts/gen-fixtures.sh`.

Never commit exports from a real Keycloak instance.

## Pull requests

- Keep each pull request to one change.
- Run the tests and the linter before pushing.
- Explain why the change is needed, not only what it does.
