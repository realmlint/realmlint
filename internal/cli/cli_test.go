package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"no args shows usage", nil, ExitUsage, "", "Usage:"},
		{"help", []string{"--help"}, ExitOK, "Usage:", ""},
		{"short help", []string{"-h"}, ExitOK, "Usage:", ""},
		{"version flag", []string{"--version"}, ExitOK, "realmlint dev\n", ""},
		{"version command", []string{"version"}, ExitOK, "realmlint dev\n", ""},
		{"unknown command", []string{"lint"}, ExitUsage, "", `unknown command "lint"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) || (tt.wantStdout == "" && stdout.Len() > 0) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) || (tt.wantStderr == "" && stderr.Len() > 0) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}
