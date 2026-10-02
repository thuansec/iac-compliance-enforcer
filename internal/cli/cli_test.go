package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const versionJSON = `{
  "schema_version": "1",
  "name": "iace",
  "version": "dev",
  "commit": "dev",
  "date": "dev"
}
`

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string // exact
		wantStderr string // exact
	}{
		{
			name:       "version prints build info",
			args:       []string{"version"},
			wantCode:   0,
			wantStdout: "iace dev (commit dev, built dev)\n",
		},
		{
			name:       "version --json prints the versioned document",
			args:       []string{"version", "--json"},
			wantCode:   0,
			wantStdout: versionJSON,
		},
		{
			name:       "unknown flag is a usage error",
			args:       []string{"version", "--bogus"},
			wantCode:   2,
			wantStderr: "iace: unknown flag: --bogus; see 'iace --help'\n",
		},
		{
			name:       "unknown command is a usage error",
			args:       []string{"bogus"},
			wantCode:   2,
			wantStderr: "iace: unknown command \"bogus\" for \"iace\"; see 'iace --help'\n",
		},
		{
			name:       "version takes no arguments",
			args:       []string{"version", "extra"},
			wantCode:   2,
			wantStderr: "iace: unknown command \"extra\" for \"iace version\"; see 'iace --help'\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr %q)", code, tt.wantCode, stderr.String())
			}
			if got := stdout.String(); got != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", got, tt.wantStdout)
			}
			if got := stderr.String(); got != tt.wantStderr {
				t.Errorf("stderr = %q, want %q", got, tt.wantStderr)
			}
		})
	}
}

var errWrite = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

// A report that cannot be written is an error (exit 2), never a silent success.
func TestVersionWriteErrorFailsClosed(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{{"version"}, {"version", "--json"}} {
		var stderr bytes.Buffer
		if code := Run(context.Background(), args, failingWriter{}, &stderr); code != exitError {
			t.Errorf("%v: exit code = %d, want %d", args, code, exitError)
		}
		if want := "iace: write version: write failed; see 'iace --help'\n"; stderr.String() != want {
			t.Errorf("%v: stderr = %q, want %q", args, stderr.String(), want)
		}
	}
}

func TestHelpGoesToStdout(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"version", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "iace version --json") {
		t.Errorf("help does not show the --json example:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

// Nil args must not fall back to the process arguments, which cobra does by default. Under
// `go test` those are all -test.* flags, which hide the fallback, so the test re-runs its own
// binary with a positional argument that iace would reject as an unknown command.
func TestNilArgsIgnoresProcessArguments(t *testing.T) {
	if os.Getenv("IACE_TEST_NIL_ARGS_HELPER") == "1" {
		os.Exit(Run(context.Background(), nil, io.Discard, os.Stderr))
	}
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestNilArgsIgnoresProcessArguments$", "not-an-iace-command")
	cmd.Env = append(os.Environ(), "IACE_TEST_NIL_ARGS_HELPER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("Run(nil) read the process arguments: %v\n%s", err, out)
	}
}

// The CLI contract requires a runnable example in every command's --help.
func TestEveryCommandHasAnExample(t *testing.T) {
	t.Parallel()

	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		if strings.TrimSpace(cmd.Example) == "" {
			t.Errorf("command %q has no Example", cmd.CommandPath())
		}
		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}
	root := newRootCommand()
	root.InitDefaultHelpCmd() // cobra adds its help command lazily, during Execute
	walk(root)
}
