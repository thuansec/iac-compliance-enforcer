package terraform_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// tree creates files under a temp dir. Content is a fake Terraform comment.
func tree(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("# fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func discover(t *testing.T, dir string, limits terraform.Limits) *terraform.Discovery {
	t.Helper()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	d, err := terraform.Discover(context.Background(), r, limits)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return d
}

func TestDiscoverListsTerraformFilesPerDirectory(t *testing.T) {
	t.Parallel()
	dir := tree(t,
		"main.tf",
		"variables.tf",
		"modules/net/vars.tf.json",
		"modules/net/main.tf",
		"modules/net/README.md",
		"modules/empty/notes.txt",
		"envs/prod/main.tf",
		".terraform/modules/vpc/main.tf",
		".git/hooks/x.tf",
		".github/workflows/x.tf",
		"envs/.cache/a.tf",
		"envs/prod/.hidden.tf",
		"envs/prod/main.tf~",
		"envs/prod/#main.tf#",
		"envs/prod/main.tfvars",
		"envs/prod/main.tf.bak",
	)
	got := discover(t, dir, terraform.DefaultLimits())
	want := &terraform.Discovery{
		Dirs: []terraform.Dir{
			{Path: ".", Files: []string{"main.tf", "variables.tf"}},
			{Path: "envs/prod", Files: []string{"envs/prod/main.tf"}},
			{Path: "modules/net", Files: []string{"modules/net/main.tf", "modules/net/vars.tf.json"}},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Discover (-want +got):\n%s", diff)
	}
}

func TestDiscoverSkipsOversizedFiles(t *testing.T) {
	t.Parallel()
	dir := tree(t, "main.tf", "big/huge.tf")
	// A sparse file one byte over the default 5 MiB limit.
	if err := os.Truncate(filepath.Join(dir, "big", "huge.tf"), 5<<20+1); err != nil {
		t.Fatal(err)
	}
	got := discover(t, dir, terraform.DefaultLimits())
	want := &terraform.Discovery{
		Dirs: []terraform.Dir{{Path: ".", Files: []string{"main.tf"}}},
		Skipped: []terraform.Skip{{
			Path: "big/huge.tf", Reason: terraform.SkipTooLarge, Detail: "5242881 bytes, limit 5242880",
		}},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Discover (-want +got):\n%s", diff)
	}
}

func TestDiscoverFileLimitBoundaries(t *testing.T) {
	t.Parallel()
	files := []string{"a/1.tf", "a/2.tf", "b/1.tf", "b/2.tf", "c/1.tf"}
	limitSkip := func(path string, n int) []terraform.Skip {
		return []terraform.Skip{{
			Path: path, Reason: terraform.SkipFileLimit,
			Detail: fmt.Sprintf("more than %d Terraform files and skipped entries; this entry and the rest of the scan root were not discovered", n),
		}}
	}
	tests := []struct {
		name     string
		maxFiles int
		want     *terraform.Discovery
	}{
		{"below the limit", 6, &terraform.Discovery{Dirs: []terraform.Dir{
			{Path: "a", Files: []string{"a/1.tf", "a/2.tf"}},
			{Path: "b", Files: []string{"b/1.tf", "b/2.tf"}},
			{Path: "c", Files: []string{"c/1.tf"}},
		}}},
		{"exactly the limit", 5, &terraform.Discovery{Dirs: []terraform.Dir{
			{Path: "a", Files: []string{"a/1.tf", "a/2.tf"}},
			{Path: "b", Files: []string{"b/1.tf", "b/2.tf"}},
			{Path: "c", Files: []string{"c/1.tf"}},
		}}},
		{"one over the limit", 4, &terraform.Discovery{
			Dirs: []terraform.Dir{
				{Path: "a", Files: []string{"a/1.tf", "a/2.tf"}},
				{Path: "b", Files: []string{"b/1.tf", "b/2.tf"}},
			},
			Skipped: limitSkip("c/1.tf", 4),
		}},
		{"well over the limit", 3, &terraform.Discovery{
			Dirs: []terraform.Dir{
				{Path: "a", Files: []string{"a/1.tf", "a/2.tf"}},
				{Path: "b", Files: []string{"b/1.tf"}},
			},
			Skipped: limitSkip("b/2.tf", 3),
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := discover(t, tree(t, files...), terraform.Limits{MaxFileSize: 1024, MaxFiles: tc.maxFiles})
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Discover (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDiscoverCountsSkippedEntriesTowardTheLimit(t *testing.T) {
	t.Parallel()
	// Every file is over a 1-byte size limit, so all are skipped; the skips still count.
	got := discover(t, tree(t, "1.tf", "2.tf", "3.tf"), terraform.Limits{MaxFileSize: 1, MaxFiles: 2})
	var reasons []terraform.SkipReason
	for _, s := range got.Skipped {
		reasons = append(reasons, s.Reason)
	}
	want := []terraform.SkipReason{terraform.SkipTooLarge, terraform.SkipTooLarge, terraform.SkipFileLimit}
	if diff := cmp.Diff(want, reasons); diff != "" {
		t.Errorf("skip reasons (-want +got):\n%s", diff)
	}
}

func TestDiscoverAcceptsAFileAtTheSizeLimit(t *testing.T) {
	t.Parallel()
	dir := tree(t, "exact.tf")
	if err := os.Truncate(filepath.Join(dir, "exact.tf"), 5<<20); err != nil {
		t.Fatal(err)
	}
	got := discover(t, dir, terraform.DefaultLimits())
	want := &terraform.Discovery{Dirs: []terraform.Dir{{Path: ".", Files: []string{"exact.tf"}}}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Discover (-want +got):\n%s", diff)
	}
}

func TestDiscoverEmptyRoot(t *testing.T) {
	t.Parallel()
	got := discover(t, t.TempDir(), terraform.DefaultLimits())
	if len(got.Dirs) != 0 || len(got.Skipped) != 0 {
		t.Errorf("Discover(empty) = %+v, want nothing", got)
	}
}

func TestDiscoverHonoursCancellation(t *testing.T) {
	t.Parallel()
	r, err := fsutil.OpenRoot(tree(t, "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := terraform.Discover(ctx, r, terraform.DefaultLimits()); err == nil {
		t.Error("Discover with a cancelled context succeeded, want an error")
	}
}

func TestDiscoverRejectsInvalidLimits(t *testing.T) {
	t.Parallel()
	r, err := fsutil.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	for _, l := range []terraform.Limits{{MaxFileSize: 0, MaxFiles: 1}, {MaxFileSize: 1, MaxFiles: 0}} {
		if _, err := terraform.Discover(context.Background(), r, l); err == nil {
			t.Errorf("Discover(%+v) succeeded, want an error", l)
		}
	}
}

func TestSkipString(t *testing.T) {
	t.Parallel()
	s := terraform.Skip{Path: "big/huge.tf", Reason: terraform.SkipTooLarge, Detail: "6 bytes, limit 5"}
	got := s.String()
	for _, want := range []string{`"big/huge.tf"`, "too_large", "6 bytes, limit 5"} {
		if !strings.Contains(got, want) {
			t.Errorf("Skip.String() = %q, missing %q", got, want)
		}
	}

	forged := terraform.Skip{Path: "x.tf\n::error::forged", Reason: terraform.SkipTooLarge, Detail: "d"}.String()
	if strings.Contains(forged, "\n") {
		t.Errorf("Skip.String() passes a newline from the path through: %q", forged)
	}
}
