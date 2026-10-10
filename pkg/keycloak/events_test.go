package keycloak

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A client without view-events may read the realm but not its admin
// events; that is reported as ErrEventsForbidden, not a failed request.
func TestAdminEventsForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/token"):
			_, _ = w.Write([]byte(`{"access_token":"t","expires_in":300}`))
		case strings.HasSuffix(r.URL.Path, "/admin-events"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"HTTP 403 Forbidden"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "master", "realmlint-agent", "s")
	_, err := c.AdminEvents(context.Background(), "wanderoon", time.Now().Add(-time.Hour))
	if !errors.Is(err, ErrEventsForbidden) {
		t.Fatalf("err = %v, want ErrEventsForbidden", err)
	}
}
