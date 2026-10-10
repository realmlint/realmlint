package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// backupStore writes realm exports to the customer's own storage: a
// directory, or an S3 bucket with the credentials of the agent's
// environment. realmlint never holds these credentials.
type backupStore interface {
	put(ctx context.Context, key string, data []byte) error
	// where names the target without secrets, for logs and the portal.
	where() string
}

// newBackupStore parses --backup-to: a directory, or s3://bucket/prefix.
// endpoint, if set, points at an S3-compatible service instead of AWS.
func newBackupStore(ctx context.Context, target, endpoint string) (backupStore, error) {
	if !strings.HasPrefix(target, "s3://") {
		if strings.Contains(target, "://") {
			return nil, fmt.Errorf("--backup-to must be a directory or s3://bucket/prefix")
		}
		return dirStore(target), nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("--backup-to %q is not a valid s3://bucket/prefix", target)
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("AWS credentials for backups: %w", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true
		}
		if o.Region == "" {
			o.Region = "us-east-1"
		}
	})
	return &s3Store{client: client, bucket: u.Host, prefix: strings.Trim(u.Path, "/")}, nil
}

type dirStore string

func (d dirStore) put(_ context.Context, key string, data []byte) error {
	p := filepath.Join(string(d), filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

func (d dirStore) where() string { return "directory " + string(d) }

type s3Store struct {
	client         *s3.Client
	bucket, prefix string
}

func (s *s3Store) put(ctx context.Context, key string, data []byte) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(path.Join(s.prefix, key)),
		Body: bytes.NewReader(data), ContentType: aws.String("application/json"),
	})
	return err
}

func (s *s3Store) where() string { return "s3://" + path.Join(s.bucket, s.prefix) }

// backupKey names one realm's export: <realm>/<UTC time>.json, so a bucket
// listing sorts by date and lifecycle rules can expire old ones.
func backupKey(realmName string, at time.Time) string {
	return safeName(realmName) + "/" + at.UTC().Format("2006-01-02T150405Z") + ".json"
}

// backup writes every realm's snapshot. The snapshots are the ones sent to
// realmlint: secrets are already masked.
func backup(ctx context.Context, store backupStore, snapshots map[string]map[string]any, at time.Time) error {
	var failed []string
	for name, snap := range snapshots {
		data, err := json.MarshalIndent(snap, "", "  ")
		if err == nil {
			err = store.put(ctx, backupKey(name, at), append(data, '\n'))
		}
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}
