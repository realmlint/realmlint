#!/usr/bin/env bash
# Runs realmlint upgrade for the GitHub Action (action.yml) when the
# upgrade-to input is set. Inputs arrive as environment variables. The text
# report goes to the log, the Markdown report (with links to Keycloak's
# upgrading guide) to the job summary. The exit code is passed on through
# the step output upgrade-exit-code.
set -uo pipefail

: "${RL_PATHS:?paths input is required}"
: "${RL_UPGRADE_TO:?upgrade-to input is required}"
: "${GITHUB_OUTPUT:?not running in GitHub Actions}"

args=()
[[ "$RL_UPGRADE_TO" != "latest" ]] && args+=(--to "$RL_UPGRADE_TO")
[[ -n "${RL_UPGRADE_FROM:-}" ]] && args+=(--from "$RL_UPGRADE_FROM")

# shellcheck disable=SC2206
paths=($RL_PATHS)
[[ ${#paths[@]} -gt 0 ]] || { echo "realmlint: no paths matched '$RL_PATHS'" >&2; exit 2; }

realmlint upgrade ${args[@]+"${args[@]}"} "${paths[@]}"
code=$?

if [[ -n "${GITHUB_STEP_SUMMARY:-}" && $code -ne 2 ]]; then
  realmlint upgrade ${args[@]+"${args[@]}"} --format markdown "${paths[@]}" >>"$GITHUB_STEP_SUMMARY"
fi

echo "upgrade-exit-code=$code" >>"$GITHUB_OUTPUT"
[[ $code -eq 2 ]] && exit 2
exit 0
