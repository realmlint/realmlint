#!/usr/bin/env bash
# Runs realmlint for the GitHub Action (action.yml). Inputs arrive as
# environment variables. Writes the text report to the log and the job
# summary, and a SARIF file when requested. The exit code is passed on
# through the step output exit-code so the SARIF upload can run first.
set -uo pipefail

: "${RL_PATHS:?paths input is required}"
: "${GITHUB_OUTPUT:?not running in GitHub Actions}"

args=()
[[ -n "${RL_MIN_SEVERITY:-}" ]] && args+=(--min-severity "$RL_MIN_SEVERITY")
[[ -n "${RL_CONFIG:-}" ]] && args+=(--config "$RL_CONFIG")

# Paths are split on whitespace and globs expand, so "exports/*.json" works.
# shellcheck disable=SC2206
paths=($RL_PATHS)
[[ ${#paths[@]} -gt 0 ]] || { echo "realmlint: no paths matched '$RL_PATHS'" >&2; exit 2; }

report="${RUNNER_TEMP:-/tmp}/realmlint.txt"
fail_args=()
[[ -n "${RL_FAIL_ON:-}" ]] && fail_args=(--fail-on "$RL_FAIL_ON")
realmlint check ${args[@]+"${args[@]}"} ${fail_args[@]+"${fail_args[@]}"} "${paths[@]}" | tee "$report"
code=${PIPESTATUS[0]}

if [[ -n "${GITHUB_STEP_SUMMARY:-}" && $code -ne 2 ]]; then
  {
    echo "### realmlint"
    echo
    echo '```'
    cat "$report"
    echo '```'
  } >>"$GITHUB_STEP_SUMMARY"
fi

if [[ "${RL_SARIF:-true}" == "true" && $code -ne 2 ]]; then
  sarif="${RUNNER_TEMP:-/tmp}/realmlint.sarif"
  realmlint check ${args[@]+"${args[@]}"} --format sarif --fail-on none "${paths[@]}" >"$sarif" || code=2
  echo "sarif-file=$sarif" >>"$GITHUB_OUTPUT"
fi

echo "exit-code=$code" >>"$GITHUB_OUTPUT"
# Usage and input errors stop the action here; findings fail it after the
# SARIF upload.
[[ $code -eq 2 ]] && exit 2
exit 0
