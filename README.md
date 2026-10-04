# realmlint

Lint and diff Keycloak realm configuration.

Status: pre-release, under development.

## Development

Requires Go 1.27+. Regenerating fixtures also requires Docker.

```
go test ./...                  # unit tests
golangci-lint run ./...        # lint (golangci-lint v2)
go build ./cmd/realmlint       # build the binary
scripts/gen-fixtures.sh        # regenerate testdata/realms from real Keycloak releases
```

Test fixtures in `testdata/realms` are real `kc.sh export` output from the
synthetic seed realm in `testdata/seed`, with secrets masked. Supported
Keycloak versions are the latest three 26.x minor releases, listed in
`scripts/gen-fixtures.sh`.
