//go:build unix

package fsutil_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

func TestReadFileRefusesSymlinkEscapes(t *testing.T) {
	t.Parallel()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.tf"), []byte("outside"))
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "inside.tf"), []byte("inside"))
	links := map[string]string{
		"relative-escape.tf": filepath.Join("..", filepath.Base(outside), "secret.tf"),
		"absolute-escape.tf": filepath.Join(outside, "secret.tf"),
		"inside-link.tf":     "inside.tf",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	r := openRoot(t, dir)

	for _, name := range []string{"relative-escape.tf", "absolute-escape.tf"} {
		if data, err := r.ReadFile(name, 1024); err == nil {
			t.Errorf("ReadFile(%s) = %q, want an escape error", name, data)
		}
	}
	data, err := r.ReadFile("inside-link.tf", 1024)
	if err != nil || string(data) != "inside" {
		t.Errorf("ReadFile(inside-link.tf) = %q, %v; want the target inside the root", data, err)
	}
}

func TestReadFileRefusesFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.tf"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := openRoot(t, dir)

	done := make(chan error, 1)
	go func() {
		_, err := r.ReadFile("pipe.tf", 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, fsutil.ErrNotRegular) {
			t.Errorf("ReadFile(pipe.tf) error = %v, want ErrNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFile blocked on a FIFO")
	}
}

func TestStatFollowsSymlinksOnlyInsideTheRoot(t *testing.T) {
	t.Parallel()
	outside := t.TempDir()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "sub", "main.tf"), []byte("inside"))
	if err := os.Symlink("sub", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "away")); err != nil {
		t.Fatal(err)
	}
	r := openRoot(t, dir)

	fi, err := r.Stat("alias")
	if err != nil || !fi.IsDir() {
		t.Errorf("Stat(alias) = %v, %v; want the directory inside the root", fi, err)
	}
	if _, err := r.Stat("away"); err == nil {
		t.Error("Stat(away) succeeded, want an escape error")
	}
	if _, err := r.Stat("sub/../../x"); err == nil {
		t.Error("Stat(sub/../../x) succeeded, want an escape error")
	}
}
