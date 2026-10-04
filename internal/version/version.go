// Package version reports the realmlint build version.
package version

import "runtime/debug"

// Version is the release version. Release builds set it through
// main.version (see cmd/realmlint).
var Version = "dev"

// String returns the release version if one was set at build time.
// Otherwise it returns the module version Go recorded in the binary: the
// tagged version for `go install`, or a pseudo-version from the git commit
// for local builds. It falls back to "dev" when neither is available.
func String() string {
	if Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return Version
}
