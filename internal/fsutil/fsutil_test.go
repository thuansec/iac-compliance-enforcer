package fsutil_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func openRoot(t *testing.T, dir string) *fsutil.Root {
	t.Helper()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestReadFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a", "main.tf"), []byte("12345"))
	r := openRoot(t, dir)

	tests := []struct {
		name    string
		path    string
		max     int64
		want    string
		wantErr error
		errText string
	}{
		{name: "within the limit", path: "a/main.tf", max: 10, want: "12345"},
		{name: "exactly the limit", path: "a/main.tf", max: 5, want: "12345"},
		{name: "over the limit", path: "a/main.tf", max: 4, wantErr: fsutil.ErrTooLarge, errText: "a/main.tf"},
		{name: "a directory", path: "a", max: 10, wantErr: fsutil.ErrNotRegular, errText: "a"},
		{name: "parent escape", path: "../outside.tf", max: 10, errText: "../outside.tf"},
		{name: "absolute path", path: "/etc/hostname", max: 10, errText: "/etc/hostname"},
		{name: "missing file", path: "a/none.tf", max: 10, wantErr: os.ErrNotExist, errText: "a/none.tf"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := r.ReadFile(tc.path, tc.max)
			if tc.errText == "" {
				if err != nil {
					t.Fatalf("ReadFile: %v", err)
				}
				if string(got) != tc.want {
					t.Errorf("ReadFile = %q, want %q", got, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("ReadFile succeeded with %q, want an error", got)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error %v is not %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.errText) {
				t.Errorf("error %q does not name %q", err, tc.errText)
			}
		})
	}
}

func TestReadDirIsSorted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, n := range []string{"b.tf", "a.tf", "c"} {
		writeFile(t, filepath.Join(dir, "m", n), nil)
	}
	r := openRoot(t, dir)
	entries, err := r.ReadDir("m")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if got := strings.Join(names, ","); got != "a.tf,b.tf,c" {
		t.Errorf("ReadDir names = %s, want a.tf,b.tf,c", got)
	}
	if _, err := r.ReadDir("../"); err == nil {
		t.Error("ReadDir(../) succeeded, want an escape error")
	}
}

func TestOpenRootMissingDir(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing")
	_, err := fsutil.OpenRoot(missing)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("OpenRoot(missing) = %v, want an error naming the directory", err)
	}
}

func TestErrorsNeverCarryANewlineFromThePath(t *testing.T) {
	t.Parallel()
	r := openRoot(t, t.TempDir())
	const name = "x\n::error::forged.tf"
	calls := map[string]func() error{
		"ReadDir":  func() error { _, err := r.ReadDir(name); return err },
		"Stat":     func() error { _, err := r.Stat(name); return err },
		"Lstat":    func() error { _, err := r.Lstat(name); return err },
		"ReadFile": func() error { _, err := r.ReadFile(name, 10); return err },
	}
	for op, call := range calls {
		err := call()
		if err == nil {
			t.Errorf("%s(%q) succeeded, want an error", op, name)
			continue
		}
		if strings.Contains(err.Error(), "\n") {
			t.Errorf("%s error contains a raw newline from the path: %q", op, err)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s error %v no longer matches os.ErrNotExist", op, err)
		}
	}
}
