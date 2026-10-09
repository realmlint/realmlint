package check

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/realmlint/realmlint/pkg/realm"
)

const (
	certExpiryWarning = 30 * 24 * time.Hour
	keyRotationAge    = 365 * 24 * time.Hour
)

// OldestSupportedVersion is the oldest Keycloak minor release realmlint is
// tested against. Keep it in line with VERSIONS in scripts/gen-fixtures.sh.
const OldestSupportedVersion = "26.6"

var expiryChecks = []Check{
	{
		ID:    "key-certificate-expiry",
		Title: "Realm key certificate is expiring",
		Why:   "Clients and identity brokers verify tokens and SAML assertions against the realm key's certificate. When it expires, they start rejecting logins.",
		Fix:   "In Realm settings > Keys > Providers, add a new key provider with a higher priority, wait for clients to pick it up, then disable the old one.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for _, k := range activeKeys(ctx.Realm) {
				cert := parseCert(k.Config.First("certificate"))
				if cert == nil {
					continue
				}
				if f, ok := expiryFinding(cert, ctx.Now); ok {
					f.Object = keyObject(k)
					findings = append(findings, f)
				}
			}
			return findings
		},
	},
	{
		ID:    "key-not-rotated",
		Title: "Realm signing key has not been rotated",
		Why:   "Keys that are never rotated give a leaked private key unlimited time to be abused. Generated keys come with 10-year certificates, so they never force a rotation.",
		Fix:   "Rotate the key at least yearly: add a new key provider with a higher priority, then disable and later remove the old one.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for _, k := range activeKeys(ctx.Realm) {
				cert := parseCert(k.Config.First("certificate"))
				if cert == nil {
					continue
				}
				if age := ctx.Now.Sub(cert.NotBefore); age > keyRotationAge {
					findings = append(findings, Finding{
						Severity: Low,
						Object:   keyObject(k),
						Message:  fmt.Sprintf("key certificate was issued %s (%d days ago)", cert.NotBefore.Format(time.DateOnly), int(age.Hours()/24)),
					})
				}
			}
			return findings
		},
	},
	{
		ID:    "idp-certificate-expiry",
		Title: "Identity provider certificate is expiring",
		Why:   "Keycloak verifies the identity provider's signatures with this certificate. When the provider rotates to a new certificate, or this one expires, logins through the provider fail.",
		Fix:   "Get the provider's current signing certificate (or import its metadata again) and update the identity provider's Validating X509 certificates.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for i := range ctx.Realm.IdentityProviders {
				idp := &ctx.Realm.IdentityProviders[i]
				if !idp.Enabled {
					continue
				}
				for _, raw := range strings.Split(idp.Config["signingCertificate"], ",") {
					cert := parseCert(raw)
					if cert == nil {
						continue
					}
					if f, ok := expiryFinding(cert, ctx.Now); ok {
						f.Object = idpObject(idp)
						findings = append(findings, f)
					}
				}
			}
			return findings
		},
	},
	{
		ID:    "idp-signature-not-validated",
		Title: "SAML identity provider signatures are not checked",
		Why:   "Without signature validation, anyone who can reach Keycloak can forge a SAML response and log in as any user of that provider.",
		Fix:   "In the identity provider's settings, turn on Validate signatures and add the provider's signing certificate.",
		Run: func(ctx *Context) []Finding {
			var findings []Finding
			for i := range ctx.Realm.IdentityProviders {
				idp := &ctx.Realm.IdentityProviders[i]
				if !idp.Enabled || idp.ProviderID != "saml" || idp.Config["validateSignature"] == "true" {
					continue
				}
				findings = append(findings, Finding{Severity: High, Object: idpObject(idp), Message: "SAML signature validation is off"})
			}
			return findings
		},
	},
	{
		ID:      "keycloak-version-outdated",
		Setting: "keycloakVersion",
		Title:   "Keycloak version is out of date",
		Why:     "Older Keycloak releases miss security fixes, and realmlint's checks are only tested against recent releases.",
		Fix:     "Upgrade Keycloak to the latest 26.x release, reading the upgrade notes for each minor release in between.",
		Run: func(ctx *Context) []Finding {
			v := ctx.Realm.KeycloakVersion
			if v == "" || !versionBefore(v, OldestSupportedVersion) {
				return nil
			}
			// Report once per run, on the first realm with this version.
			for _, r := range ctx.Realms {
				if r.KeycloakVersion == v {
					if r != ctx.Realm {
						return nil
					}
					break
				}
			}
			return []Finding{{
				Severity: Medium,
				Message:  fmt.Sprintf("export was made by Keycloak %s; realmlint supports %s and later", v, OldestSupportedVersion),
			}}
		},
	},
}

// activeKeys returns the realm's key providers that are enabled and active.
// Keycloak leaves these config values out when they are true.
func activeKeys(r *realm.Realm) []*realm.Component {
	var out []*realm.Component
	keys := r.ComponentsOf(realm.KeyProviderType)
	for i := range keys {
		k := &keys[i]
		if k.Config.First("enabled") == "false" || k.Config.First("active") == "false" {
			continue
		}
		out = append(out, k)
	}
	return out
}

func expiryFinding(cert *x509.Certificate, now time.Time) (Finding, bool) {
	left := cert.NotAfter.Sub(now)
	switch {
	case left <= 0:
		return Finding{Severity: Critical, Message: fmt.Sprintf("certificate expired on %s", cert.NotAfter.Format(time.DateOnly))}, true
	case left < certExpiryWarning:
		return Finding{Severity: High, Message: fmt.Sprintf("certificate expires on %s (in %d days)", cert.NotAfter.Format(time.DateOnly), int(left.Hours()/24))}, true
	}
	return Finding{}, false
}

// parseCert reads a certificate as Keycloak stores it: base64 DER without
// PEM headers. PEM is accepted too. It returns nil for anything unreadable,
// such as an empty or masked value.
func parseCert(s string) *x509.Certificate {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var der []byte
	if block, _ := pem.Decode([]byte(s)); block != nil {
		der = block.Bytes
	} else {
		var err error
		der, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil
		}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert
}

func keyObject(k *realm.Component) string {
	return fmt.Sprintf("key %q (%s)", k.Name, k.ProviderID)
}

func idpObject(idp *realm.IdentityProvider) string {
	return fmt.Sprintf("identity provider %q", idp.Alias)
}

// versionBefore reports whether version v (such as "26.5.3") is older than
// the major.minor release min (such as "26.6"). Unparseable versions are
// never reported as older.
func versionBefore(v, minVersion string) bool {
	vMajor, vMinor, ok1 := majorMinor(v)
	mMajor, mMinor, ok2 := majorMinor(minVersion)
	if !ok1 || !ok2 {
		return false
	}
	if vMajor != mMajor {
		return vMajor < mMajor
	}
	return vMinor < mMinor
}

func majorMinor(v string) (major, minor int, ok bool) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	return major, minor, err1 == nil && err2 == nil
}
