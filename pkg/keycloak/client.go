// Package keycloak reads realm configuration from a running Keycloak through
// its admin REST API, using a client with view-only permissions, and builds
// snapshots in the same shape as `kc.sh export`.
//
// The client's service account needs the realm-management roles view-realm,
// view-clients, view-users, view-events and view-identity-providers. If the
// client has full scope turned off, the same roles must be in its scope
// mappings.
package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// pageSize is how many items are requested per page from list endpoints.
const pageSize = 100

// Client calls the Keycloak admin REST API with a client-credentials token.
type Client struct {
	baseURL      string
	authRealm    string
	clientID     string
	clientSecret string
	http         *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewClient returns a client for the Keycloak at baseURL (for example
// https://sso.example.com). authRealm is the realm the agent's client lives
// in.
func NewClient(baseURL, authRealm, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		authRealm:    authRealm,
		clientID:     clientID,
		clientSecret: clientSecret,
		http:         &http.Client{Timeout: 30 * time.Second},
	}
}

// APIError is returned for unsuccessful responses.
type APIError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("%s %s: HTTP %d", e.Method, e.Path, e.Status)
	if e.Status == http.StatusForbidden {
		msg += " (check the agent client's roles and, with full scope off, its scope mappings)"
	}
	if e.Body != "" {
		msg += ": " + e.Body
	}
	return msg
}

// accessToken returns a valid token, logging in again shortly before the
// current one expires.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	path := "/realms/" + url.PathEscape(c.authRealm) + "/protocol/openid-connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("log in to Keycloak: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("log in to Keycloak as client %q in realm %q: HTTP %d: %s",
			c.clientID, c.authRealm, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return "", errors.New("log in to Keycloak: no access token in the response")
	}
	c.token = tok.AccessToken
	// Refresh 30 seconds early so a token never expires mid-request.
	c.expires = time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - 30*time.Second)
	return c.token, nil
}

// get fetches an admin API path (relative to /admin) and decodes the JSON
// response into out.
func (c *Client) get(ctx context.Context, path string, out any) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/admin"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return &APIError{Method: http.MethodGet, Path: path, Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("GET %s: invalid JSON: %w", path, err)
	}
	return nil
}

// getList fetches every page of a list endpoint. path must not already
// contain first or max.
func (c *Client) getList(ctx context.Context, path string) ([]map[string]any, error) {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	var all []map[string]any
	previousFirst := ""
	for first := 0; ; first += pageSize {
		var page []map[string]any
		if err := c.get(ctx, fmt.Sprintf("%s%sfirst=%d&max=%d", path, sep, first, pageSize), &page); err != nil {
			return nil, err
		}
		// An endpoint that ignores paging returns everything at once, or the
		// same page again; stop rather than loop.
		if len(page) > 0 && first > 0 && fmt.Sprint(page[0]["id"]) == previousFirst {
			return all, nil
		}
		all = append(all, page...)
		if len(page) < pageSize || len(page) > pageSize {
			return all, nil
		}
		previousFirst = fmt.Sprint(page[0]["id"])
	}
}
