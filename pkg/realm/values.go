package realm

import (
	"bytes"
	"encoding/json"
)

// Attributes is a string map such as client or realm attributes. Keycloak
// writes these as strings, but hand-edited exports sometimes use JSON
// booleans or numbers, so any scalar is accepted and kept as its JSON text.
type Attributes map[string]string

// UnmarshalJSON implements json.Unmarshaler.
func (a *Attributes) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		*a = nil
		return nil
	}
	out := make(Attributes, len(raw))
	for k, v := range raw {
		out[k] = scalarText(v)
	}
	*a = out
	return nil
}

// MultiValue is a component config map, where Keycloak stores every value as
// a list of strings. A single scalar is accepted as a one-item list.
type MultiValue map[string][]string

// UnmarshalJSON implements json.Unmarshaler.
func (m *MultiValue) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		*m = nil
		return nil
	}
	out := make(MultiValue, len(raw))
	for k, v := range raw {
		var list []json.RawMessage
		if err := json.Unmarshal(v, &list); err == nil {
			vals := make([]string, 0, len(list))
			for _, item := range list {
				vals = append(vals, scalarText(item))
			}
			out[k] = vals
			continue
		}
		out[k] = []string{scalarText(v)}
	}
	*m = out
	return nil
}

// First returns the first value for key, or "" if there is none.
func (m MultiValue) First(key string) string {
	if vals := m[key]; len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// scalarText returns a JSON string's value, "" for null, and the raw JSON
// text for anything else.
func scalarText(v json.RawMessage) string {
	v = bytes.TrimSpace(v)
	if bytes.Equal(v, []byte("null")) {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return s
	}
	return string(v)
}
