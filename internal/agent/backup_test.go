package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// fakeService answers /v1/agent-config with on and records backup reports.
func fakeService(t *testing.T, on bool) (*httptest.Server, *[]backupReport) {
	t.Helper()
	var reports []backupReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agent-config":
			_ = json.NewEncoder(w).Encode(map[string]bool{"backups": on})
		case "/v1/backup-status":
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			body, _ := io.ReadAll(zr)
			var rep backupReport
			if err := json.Unmarshal(body, &rep); err != nil {
				t.Error(err)
			}
			reports = append(reports, rep)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &reports
}

func TestBackupToDirectory(t *testing.T) {
	dir := t.TempDir()
	store, err := newBackupStore(context.Background(), dir, "")
	if err != nil {
		t.Fatal(err)
	}
	srv, reports := fakeService(t, true)
	at := time.Date(2026, 10, 10, 11, 30, 0, 0, time.UTC)
	snaps := map[string]map[string]any{"acme": {"realm": "acme", "clients": []any{map[string]any{"clientId": "web", "secret": "**********"}}}}
	var log bytes.Buffer
	if !maybeBackup(context.Background(), store, newPusher(srv.URL, "t"), snaps, at, &log) {
		t.Fatal("no backup attempted")
	}
	data, err := os.ReadFile(filepath.Join(dir, "acme", "2026-10-10T113000Z.json"))
	if err != nil {
		t.Fatalf("backup file: %v (%s)", err, log.String())
	}
	if !strings.Contains(string(data), `"realm": "acme"`) || !strings.Contains(string(data), "**********") {
		t.Errorf("backup content: %s", data)
	}
	if len(*reports) != 1 || (*reports)[0].Error != "" || (*reports)[0].Realms != 1 || (*reports)[0].Target != "directory "+dir {
		t.Errorf("reports: %+v", *reports)
	}
}

func TestBackupFollowsTheService(t *testing.T) {
	dir := t.TempDir()
	store, _ := newBackupStore(context.Background(), dir, "")
	snaps := map[string]map[string]any{"acme": {"realm": "acme"}}
	var log bytes.Buffer

	// Off in realmlint: nothing written, nothing reported.
	off, offReports := fakeService(t, false)
	if maybeBackup(context.Background(), store, newPusher(off.URL, "t"), snaps, time.Now(), &log) {
		t.Error("backed up while off")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 || len(*offReports) != 0 {
		t.Errorf("wrote %d entries, %d reports while off", len(entries), len(*offReports))
	}

	// On in realmlint without a target: the agent says so.
	on, onReports := fakeService(t, true)
	maybeBackup(context.Background(), nil, newPusher(on.URL, "t"), snaps, time.Now(), &log)
	if len(*onReports) != 1 || !strings.Contains((*onReports)[0].Error, "no --backup-to") {
		t.Errorf("reports without a target: %+v", *onReports)
	}
}

func TestBackupTargets(t *testing.T) {
	if _, err := newBackupStore(context.Background(), "https://example.com/x", ""); err == nil {
		t.Error("an https target was accepted")
	}
	s, err := newBackupStore(context.Background(), "s3://my-bucket/keycloak/prod", "")
	if err != nil {
		t.Fatal(err)
	}
	if s.where() != "s3://my-bucket/keycloak/prod" {
		t.Errorf("where = %q", s.where())
	}
	if k := backupKey("a/b", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)); k != "a_b/2026-01-02T030405Z.json" {
		t.Errorf("key = %q", k)
	}
}

// TestBackupToS3 writes to an S3-compatible service when one is given:
// REALMLINT_TEST_S3_ENDPOINT, a bucket in REALMLINT_TEST_S3_BUCKET, and
// credentials in the usual AWS variables.
func TestBackupToS3(t *testing.T) {
	endpoint, bucket := os.Getenv("REALMLINT_TEST_S3_ENDPOINT"), os.Getenv("REALMLINT_TEST_S3_BUCKET")
	if endpoint == "" || bucket == "" {
		t.Skip("set REALMLINT_TEST_S3_ENDPOINT and REALMLINT_TEST_S3_BUCKET")
	}
	ctx := context.Background()
	store, err := newBackupStore(ctx, "s3://"+bucket+"/keycloak/prod", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	// The bucket is the customer's; the test makes its own (an existing one
	// is fine).
	_, _ = store.(*s3Store).client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	if err := backup(ctx, store, map[string]map[string]any{"acme": {"realm": "acme"}}, at); err != nil {
		t.Fatal(err)
	}
	s3s := store.(*s3Store)
	out, err := s3s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: aws.String("keycloak/prod/acme/2026-10-10T120000Z.json")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Body.Close() }()
	body, _ := io.ReadAll(out.Body)
	if !strings.Contains(string(body), `"realm": "acme"`) {
		t.Errorf("object: %s", body)
	}
}
