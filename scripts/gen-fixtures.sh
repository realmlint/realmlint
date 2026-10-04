#!/usr/bin/env bash
# Regenerates realm export fixtures from real Keycloak releases.
#
# Each version imports testdata/seed/acme-realm.json into a throwaway
# Keycloak container and exports it. The newest version is exported in all
# three formats (one realm per file, all realms in one file, directory with
# separate users files); older versions only as one realm per file.
# Secrets are masked by tools/redact before the files are kept.
#
# Usage: scripts/gen-fixtures.sh            (needs Docker and Go)
set -euo pipefail

# Supported versions: the latest three minor releases. Newest first.
VERSIONS=(26.8.0 26.7.5 26.6.4)

root="$(cd "$(dirname "$0")/.." && pwd)"
out_root="$root/testdata/realms"
work="$(mktemp -d)"
trap 'rm -rf "${work:?}"' EXIT

cp "$root/testdata/seed/acme-realm.json" "$work/"

for i in "${!VERSIONS[@]}"; do
  v="${VERSIONS[$i]}"
  echo "exporting from Keycloak $v"
  mkdir -p "$work/$v"
  chmod 777 "$work/$v"

  cmds="/opt/keycloak/bin/kc.sh import --file /work/acme-realm.json
        /opt/keycloak/bin/kc.sh export --realm acme --file /work/$v/single.json"
  if [[ $i -eq 0 ]]; then
    cmds="$cmds
        /opt/keycloak/bin/kc.sh export --file /work/$v/all.json
        /opt/keycloak/bin/kc.sh export --realm acme --dir /work/$v/dir --users different_files --users-per-file 2"
  fi

  docker run --rm --entrypoint /bin/bash -v "$work:/work" "quay.io/keycloak/keycloak:$v" \
    -c "set -e; ${cmds//$'\n'/ && }" >"$work/$v.log" 2>&1 \
    || { echo "Keycloak $v failed; last lines of log:"; tail -n 50 "$work/$v.log"; exit 1; }

  rm -rf "${out_root:?}/$v"
  mkdir -p "$out_root/$v"
  cp -r "$work/$v/." "$out_root/$v/"
done

cd "$root"
find "$out_root" -name '*.json' -print0 | xargs -0 go run ./tools/redact
echo "fixtures written to $out_root"
