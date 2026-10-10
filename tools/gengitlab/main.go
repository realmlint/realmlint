// Command gengitlab writes the GitLab CI template for sending Terraform
// state to realmlint (ci/gitlab/terraform-state.yml), embedding
// scripts/post-terraform-state.sh. GitLab includes a template as a single
// file, so the script travels inside it. Run from the repository root.
package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	scriptPath   = "scripts/post-terraform-state.sh"
	templatePath = "ci/gitlab/terraform-state.yml"
)

const header = `# realmlint: send Terraform state to the realmlint portal after apply, so it
# shows Keycloak settings changed outside Terraform and who changed them.
#
# Generated from scripts/post-terraform-state.sh by tools/gengitlab. Do not
# edit; change the script and run: go run ./tools/gengitlab
#
# Set these CI/CD variables in the project:
#   REALMLINT_URL          the portal address, as on the instance's
#                          Terraform drift tab
#   REALMLINT_AGENT_TOKEN  the instance's agent token (masked, protected)
# Optional:
#   REALMLINT_TF_ROOT          where terraform init ran (default ".")
#   REALMLINT_STATE_FILE       send this terraform show -json output instead
#   REALMLINT_FAIL_ON_ERROR    "true" fails the job when the state cannot be
#                              sent; by default it only warns
#
# Use it at the end of the job that applies, where Terraform can already
# read its state (the image needs curl and gzip):
#
#   include:
#     - remote: https://raw.githubusercontent.com/realmlint/realmlint/v1/ci/gitlab/terraform-state.yml
#
#   apply:
#     script:
#       - terraform apply -auto-approve
#       - !reference [.realmlint-terraform-state, script]
#
# Or as a job of its own that extends .realmlint-terraform-state, with the
# image and terraform init your apply job uses. A failed upload then shows
# as a warning (exit code 3).

.realmlint-terraform-state:
  allow_failure:
    exit_codes: [3]
  variables:
    REALMLINT_WARN_EXIT: "3"
  script:
    - |
      RL_URL="${REALMLINT_URL:-}" RL_TOKEN="${REALMLINT_AGENT_TOKEN:-}" \
      RL_WORKING_DIRECTORY="${REALMLINT_TF_ROOT:-.}" RL_STATE_FILE="${REALMLINT_STATE_FILE:-}" \
      RL_FAIL_ON_ERROR="${REALMLINT_FAIL_ON_ERROR:-false}" RL_WARN_EXIT="${REALMLINT_WARN_EXIT:-0}" \
      sh -s <<'REALMLINT_SCRIPT'
`

const footer = "      REALMLINT_SCRIPT\n"

// render returns the template for the script's contents.
func render(script string) string {
	var b strings.Builder
	b.WriteString(header)
	for _, line := range strings.Split(strings.TrimRight(script, "\n"), "\n") {
		if line == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString("      " + line + "\n")
	}
	b.WriteString(footer)
	return b.String()
}

func main() {
	script, err := os.ReadFile(scriptPath)
	if err == nil {
		err = os.WriteFile(templatePath, []byte(render(string(script))), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gengitlab:", err)
		os.Exit(1)
	}
}
