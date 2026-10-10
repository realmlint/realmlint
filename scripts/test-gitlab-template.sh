#!/bin/sh
# Runs the script block of the GitLab CI template (ci/gitlab/terraform-state.yml)
# the way a GitLab runner would, with sh in an Alpine container, against the
# stub portal. Needs Docker and yq (both on GitHub's Ubuntu runners).
set -eu
block=$(yq '.".realmlint-terraform-state".script[0]' ci/gitlab/terraform-state.yml)
printf '%s\n' "$block" >"${RUNNER_TEMP:-/tmp}/gitlab-block.sh"
docker run --rm -v "$PWD:/w" -v "${RUNNER_TEMP:-/tmp}/gitlab-block.sh:/block.sh:ro" -w /w alpine:3 sh -euc '
  apk add -q --no-cache curl python3 >/dev/null
  python3 scripts/stub-portal.py 8765 2>/dev/null &
  for _ in $(seq 20); do curl -s -o /dev/null http://127.0.0.1:8765/ && break; sleep 0.5; done
  export REALMLINT_URL=http://127.0.0.1:8765 REALMLINT_STATE_FILE=testdata/terraform/state.json
  REALMLINT_AGENT_TOKEN=test-token sh /block.sh | grep -q "stored 1 Keycloak resources (realms: acme)"
  echo "sent: ok"
  # A wrong token warns with the warning exit code (3 in the extending job).
  set +e
  REALMLINT_AGENT_TOKEN=wrong REALMLINT_WARN_EXIT=3 sh /block.sh 2>/dev/null; code=$?
  [ "$code" = 3 ] || { echo "wrong token: exit $code, want 3"; exit 1; }
  REALMLINT_AGENT_TOKEN=wrong REALMLINT_FAIL_ON_ERROR=true sh /block.sh 2>/dev/null; code=$?
  [ "$code" = 1 ] || { echo "wrong token with fail-on-error: exit $code, want 1"; exit 1; }
  echo "failures: ok"
'
