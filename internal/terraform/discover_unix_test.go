//go:build unix

package terraform_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

func TestDiscoverSymlinksAndSpecialFiles(t *testing.T) {
	t.Parallel()
	outside := tree(t, "secret.tf", "mod/main.tf")
	dir := tree(t, "main.tf", "real/main.tf")
	symlinks := map[string]string{
		"escape.tf":        filepath.Join("..", filepath.Base(outside), "secret.tf"),
		"absolute.tf":      filepath.Join(outside, "secret.tf"),
		"outside-mod":      filepath.Join(outside, "mod"),
		"alias":            "real",
		"real/linked.tf":   "main.tf",
		"dangling.tf":      "missing.tf",
		"notes-link.md":    filepath.Join(outside, "secret.tf"),
		"loop/self":        ".",
		"loop/selfloop.tf": "selfloop.tf",
		".hidden-link":     filepath.Join(outside, "mod"),
		"real/inside.md":   "main.tf",
	}
	if err := os.MkdirAll(filepath.Join(dir, "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range symlinks {
		if err := os.Symlink(target, filepath.Join(dir, filepath.FromSlash(name))); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.tf"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := discover(t, dir, terraform.DefaultLimits())
	escape := "the symlink target cannot be resolved inside the scan root (outside it, absolute, missing or a loop)"
	want := &terraform.Discovery{
		Dirs: []terraform.Dir{
			{Path: ".", Files: []string{"main.tf"}},
			{Path: "real", Files: []string{"real/linked.tf", "real/main.tf"}},
		},
		Skipped: []terraform.Skip{
			{Path: "absolute.tf", Reason: terraform.SkipSymlinkEscape, Detail: escape},
			{Path: "alias", Reason: terraform.SkipSymlinkDir, Detail: "symlinked directories are not followed"},
			{Path: "dangling.tf", Reason: terraform.SkipSymlinkEscape, Detail: escape},
			{Path: "escape.tf", Reason: terraform.SkipSymlinkEscape, Detail: escape},
			{Path: "loop/self", Reason: terraform.SkipSymlinkDir, Detail: "symlinked directories are not followed"},
			{Path: "loop/selfloop.tf", Reason: terraform.SkipSymlinkEscape, Detail: escape},
			{Path: "notes-link.md", Reason: terraform.SkipSymlinkEscape, Detail: escape},
			{Path: "outside-mod", Reason: terraform.SkipSymlinkEscape, Detail: escape},
			{Path: "pipe.tf", Reason: terraform.SkipNotRegular, Detail: "not a regular file"},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Discover (-want +got):\n%s", diff)
	}
}

func TestDiscoverFailsOnAnUnreadableDirectory(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		return // root reads any directory, so the permission error cannot happen
	}
	dir := tree(t, "main.tf", "locked/main.tf")
	locked := filepath.Join(dir, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) }) // let t.TempDir remove it

	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	d, err := terraform.Discover(context.Background(), r, terraform.DefaultLimits())
	if err == nil {
		t.Fatalf("Discover = %+v, want an error for the unreadable directory", d)
	}
	if !strings.Contains(err.Error(), `"locked"`) {
		t.Errorf("error %q does not name the directory", err)
	}
}
