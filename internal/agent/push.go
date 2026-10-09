package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/realmlint/realmlint/internal/version"
)

// pusher sends snapshots and admin events to the hosted service.
type pusher struct {
	base  string
	token string
	http  *http.Client
}

// validatePushURL accepts https URLs, and http only for this machine, so the
// agent token never crosses a network unencrypted.
func validatePushURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("--push-url %q is not a valid URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
		return fmt.Errorf("--push-url must use https (http is only allowed for localhost)")
	default:
		return fmt.Errorf("--push-url must start with https://")
	}
}

func newPusher(base, token string) *pusher {
	return &pusher{base: strings.TrimRight(base, "/"), token: token, http: &http.Client{Timeout: 60 * time.Second}}
}

type snapshotUpload struct {
	Realm    string         `json:"realm"`
	TakenAt  time.Time      `json:"takenAt"`
	Snapshot map[string]any `json:"snapshot"`
}

type eventsUpload struct {
	Realm  string `json:"realm"`
	Events []any  `json:"events"`
}

func (p *pusher) snapshot(ctx context.Context, realmName string, takenAt time.Time, snap map[string]any) error {
	return p.post(ctx, "/v1/snapshots", snapshotUpload{Realm: realmName, TakenAt: takenAt.UTC(), Snapshot: snap})
}

func (p *pusher) events(ctx context.Context, realmName string, events []any) error {
	if events == nil {
		events = []any{}
	}
	return p.post(ctx, "/v1/admin-events", eventsUpload{Realm: realmName, Events: events})
}

// post sends v as gzip-compressed JSON.
func (p *pusher) post(ctx context.Context, path string, v any) error {
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+path, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", "realmlint-agent/"+version.String())
	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("push %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		hint := ""
		if resp.StatusCode == http.StatusUnauthorized {
			hint = " (check REALMLINT_AGENT_TOKEN)"
		}
		return fmt.Errorf("push %s: HTTP %d%s: %s", path, resp.StatusCode, hint, strings.TrimSpace(string(msg)))
	}
	return nil
}
