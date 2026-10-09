// Package redact masks secret values in Keycloak realm data.
//
// It is used by the agent before a snapshot leaves the customer's network,
// by the hosted service to reject snapshots that still contain secrets, and
// by tools/redact for test fixtures. Certificates are public and are kept,
// because expiry checks read them.
package redact

// Mask is the value Keycloak itself uses when it hides secrets in exports.
const Mask = "**********"

// SecretKeys are object fields whose values are secret wherever they appear.
var SecretKeys = map[string]bool{
	"privateKey":     true,
	"secret":         true,
	"secretData":     true,
	"credentialData": true,
	"clientSecret":   true,
	"password":       true,
	"bindCredential": true,
}

// Value masks secrets in generic JSON data (maps, slices and scalars, as
// produced by encoding/json) in place and returns it.
func Value(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if SecretKeys[k] {
				t[k] = mask(child)
				continue
			}
			t[k] = Value(child)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = Value(child)
		}
		return t
	default:
		return v
	}
}

// Leaks returns the paths of secret fields that hold a value other than the
// mask or an empty value. An empty result means the data is safe to send.
func Leaks(v any) []string {
	var out []string
	leaks(v, "", &out)
	return out
}

func leaks(v any, path string, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if SecretKeys[k] && !masked(child) {
				*out = append(*out, p)
				continue
			}
			leaks(child, p, out)
		}
	case []any:
		for _, child := range t {
			leaks(child, path+"[]", out)
		}
	}
}

// mask keeps the value's shape: component config values are string lists,
// everything else is a plain string.
func mask(v any) any {
	switch t := v.(type) {
	case []any:
		masked := make([]any, len(t))
		for i := range t {
			masked[i] = Mask
		}
		return masked
	case string:
		if t == "" {
			return t
		}
		return Mask
	default:
		return v
	}
}

func masked(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == "" || t == Mask
	case []any:
		for _, item := range t {
			if !masked(item) {
				return false
			}
		}
		return true
	default:
		// Numbers and booleans under a secret key are not secret values.
		return true
	}
}
