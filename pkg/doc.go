// Package pkg holds the packages shared by the realmlint CLI, the
// realmlint-agent and the hosted service: realm loading (realm), checks
// (check), configuration diffs (diff) and output formats (report).
//
// These packages are importable so the hosted service can use exactly the
// same logic as the CLI. Their Go API is not yet covered by the realmlint
// compatibility promise and may change between minor releases.
package pkg
