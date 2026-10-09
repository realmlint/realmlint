# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository. Do not open a public
issue.

Include the realmlint version, what you did, and what happened. If the problem
involves an export file, send a minimal synthetic export rather than a real
one.

You should get a reply within five working days. We will tell you when a fix
is released and credit you in the release notes unless you ask us not to.

## Verifying releases

Release archives, SBOMs, `checksums.txt` and the container image are built
only by `.github/workflows/release.yml` and carry signed build provenance.
Check them with `gh attestation verify <file> --repo realmlint/realmlint`, or
`gh attestation verify oci://ghcr.io/realmlint/realmlint:<version> --repo realmlint/realmlint`
for the image. A file that fails verification did not come from this
repository's release workflow; please report where you got it.

## Supported versions

Security fixes go into the latest release only.

## What counts as a vulnerability

- realmlint printing or writing a secret value from an export
- Crashes, hangs or excessive memory use caused by a crafted export or config file
- Problems in the install script or GitHub Action that could let someone run
  code or swap the binary

A check that misses a risky Keycloak setting, or reports one wrongly, is a bug,
not a vulnerability. Please open a normal issue for those.
