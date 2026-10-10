#!/usr/bin/env bash
# Posts Terraform state to realmlint so the portal can show drift, for the
# terraform-state GitHub Action (terraform-state/action.yml). Inputs arrive
# as environment variables. The state is read with `terraform show -json`
# (or from RL_STATE_FILE), gzipped, sent with the instance's agent token and
# deleted. The portal keeps only the settings it compares; secrets in the
# state are dropped on arrival.
set -uo pipefail

: "${RL_URL:?url input is required}"
: "${RL_TOKEN:?token input is required}"

fail() {
  if [[ "${RL_FAIL_ON_ERROR:-false}" == "true" ]]; then
    echo "::error::realmlint: $1"
    exit 1
  fi
  echo "::warning::realmlint: $1 Drift in the portal stays at the last upload."
  exit 0
}

tmp=$(mktemp -d "${RUNNER_TEMP:-/tmp}/realmlint-state.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

if [[ -n "${RL_STATE_FILE:-}" ]]; then
  [[ -f "$RL_STATE_FILE" ]] || fail "state file $RL_STATE_FILE does not exist."
  gzip -c "$RL_STATE_FILE" >"$tmp/state.json.gz" || fail "could not read $RL_STATE_FILE."
else
  (cd "${RL_WORKING_DIRECTORY:-.}" && "${RL_TERRAFORM:-terraform}" show -json) >"$tmp/state.json" 2>"$tmp/show.err" ||
    fail "terraform show -json failed: $(head -c 500 "$tmp/show.err")"
  gzip -c "$tmp/state.json" >"$tmp/state.json.gz"
  rm -f "$tmp/state.json"
fi

endpoint="${RL_URL%/}/v1/terraform-state"
code=$(curl -sS -o "$tmp/response" -w '%{http_code}' --retry 3 --retry-all-errors --max-time 60 \
  -X POST "$endpoint" \
  -H "Authorization: Bearer $RL_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  -H "User-Agent: realmlint-terraform-state-action" \
  --data-binary @"$tmp/state.json.gz") || fail "could not reach $endpoint."

body=$(head -c 1000 "$tmp/response")
case "$code" in
  200 | 201) ;;
  401) fail "the portal refused the token (401). Use the agent token of this instance." ;;
  422) fail "$body" ;;
  *) fail "the portal answered $code: $body" ;;
esac

# The response is {"status":"stored","resources":N,"realms":[...]}.
resources=$(tr -d '\n' <"$tmp/response" | sed -n 's/.*"resources"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p')
realms=$(tr -d '\n' <"$tmp/response" | sed -n 's/.*"realms"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' | tr -d '" ' | sed 's/,/, /g')
echo "realmlint: stored ${resources:-?} Keycloak resources (realms: ${realms:-none})."
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "resources=${resources}" >>"$GITHUB_OUTPUT"
  echo "realms=${realms}" >>"$GITHUB_OUTPUT"
fi
