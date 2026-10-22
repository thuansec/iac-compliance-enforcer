package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

func TestScanFindsAndSummarizes(t *testing.T) {
	r, err := Scan(context.Background(), filepath.Join(fixtureRoot, "IACE-AWS-EC2-001", "fail"), ScanOptions{FailOn: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 || r.Summary.High != 2 || r.Summary.Blocking != 2 || len(r.Inputs) != 1 {
		t.Errorf("report %+v", r)
	}
	if r.Findings[0].Resource.Address != "aws_instance.optional" {
		t.Errorf("findings not sorted: %v", r.Findings)
	}
}

func TestScanWithoutRootModules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("no terraform"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(context.Background(), dir, ScanOptions{FailOn: "high"}); !errors.Is(err, ErrNoRootModules) {
		t.Errorf("error %v, want ErrNoRootModules", err)
	}
}

// A setting an override file weakens is found and located in the override file (ADR 0048).
func TestScanLocatesFindingsInOverrideFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"main.tf": "resource \"aws_s3_account_public_access_block\" \"this\" {\n" +
			"  block_public_acls       = true\n  block_public_policy     = true\n" +
			"  ignore_public_acls      = true\n  restrict_public_buckets = true\n}\n",
		"main_override.tf": "# weakens the account block\nresource \"aws_s3_account_public_access_block\" \"this\" {\n" +
			"  block_public_policy = false\n}\n",
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Scan(context.Background(), dir, ScanOptions{FailOn: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings %+v, want the overridden setting only", r.Findings)
	}
	if loc := r.Findings[0].Location; loc.File != "main_override.tf" || loc.StartLine != 3 {
		t.Errorf("location %+v, want main_override.tf:3", loc)
	}
}

func TestScanPathsNamesRootsByPath(t *testing.T) {
	// Several paths must lie inside the working directory: scan from the repository root.
	t.Chdir("../..")
	fail := filepath.Join("testdata", "policies", "IACE-AWS-EC2-001", "fail")
	json := filepath.Join("testdata", "policies", "IACE-AWS-EC2-001", "fail_json")
	r, err := ScanPaths(context.Background(), []string{fail, json}, ScanOptions{FailOn: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 3 || r.Summary.High != 3 || r.Summary.Blocking != 3 || len(r.Inputs) != 2 {
		t.Fatalf("report %+v", r)
	}
	fps := map[string]bool{}
	for _, f := range r.Findings {
		if !strings.HasPrefix(f.Location.File, filepath.ToSlash(f.RootModule)+"/") {
			t.Errorf("finding %s at %s: file not under its root module", f.RootModule, f.Location.File)
		}
		if f.Fingerprint != model.Fingerprint(f.RuleID, f.RootModule, f.Resource.Address, f.AttributePath) {
			t.Errorf("fingerprint of %+v does not use the path-qualified root module", f)
		}
		fps[f.Fingerprint] = true
	}
	// aws_instance.optional exists under both paths: distinct roots, distinct fingerprints.
	if len(fps) != 3 {
		t.Errorf("%d distinct fingerprints, want 3", len(fps))
	}
}

func TestScanPathsWithOnePathIsScan(t *testing.T) {
	fail := filepath.Join(fixtureRoot, "IACE-AWS-EC2-001", "fail")
	a, err := Scan(context.Background(), fail, ScanOptions{FailOn: "high"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ScanPaths(context.Background(), []string{fail}, ScanOptions{FailOn: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Findings[0].Fingerprint != b.Findings[0].Fingerprint || b.Inputs[0] != "." {
		t.Errorf("a single path must keep scan's names: %+v vs %+v", a.Inputs, b.Inputs)
	}
}

func TestRelativePaths(t *testing.T) {
	cwd := filepath.FromSlash("/work/repo")
	got, err := RelativePaths(cwd, []string{filepath.FromSlash("/work/repo/infra/a"), "infra/b"})
	if err != nil || filepath.ToSlash(got[0]) != "infra/a" || filepath.ToSlash(got[1]) != "infra/b" {
		t.Errorf("RelativePaths = %v, %v", got, err)
	}
	var pe *PathError
	if _, err := RelativePaths(cwd, []string{"a", filepath.FromSlash("/elsewhere/b")}); !errors.As(err, &pe) {
		t.Errorf("a path outside cwd: error %v, want a PathError", err)
	}
	if _, err := RelativePaths(cwd, []string{"a", "../b"}); !errors.As(err, &pe) {
		t.Errorf("a ../ path: error %v, want a PathError", err)
	}
	if got, err := RelativePaths(cwd, []string{filepath.FromSlash("/elsewhere/only")}); err != nil || len(got) != 1 {
		t.Errorf("a single path stays as given: %v, %v", got, err)
	}
}

func TestScanPathsRejectsNestedPaths(t *testing.T) {
	var pe *PathError
	for _, paths := range [][]string{{"a", "a/b"}, {".", "a"}} {
		if _, err := ScanPaths(context.Background(), paths, ScanOptions{FailOn: "high"}); !errors.As(err, &pe) {
			t.Errorf("%v: error %v, want a PathError", paths, err)
		}
	}
}

func TestPolicyDigest(t *testing.T) {
	a := fstest.MapFS{"a.rego": {Data: []byte("x")}, "b/c.rego": {Data: []byte("y")}}
	d1, err := PolicyDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	if d2, _ := PolicyDigest(a); d1 != d2 || !strings.HasPrefix(d1, "sha256:") || len(d1) != len("sha256:")+64 {
		t.Errorf("digest %q is not a stable sha256", d1)
	}
	for name, other := range map[string]fstest.MapFS{
		"content":  {"a.rego": {Data: []byte("z")}, "b/c.rego": {Data: []byte("y")}},
		"name":     {"a2.rego": {Data: []byte("x")}, "b/c.rego": {Data: []byte("y")}},
		"boundary": {"a.rego": {Data: []byte("xb/c.rego")}},
	} {
		if d, _ := PolicyDigest(other); d == d1 {
			t.Errorf("%s change kept the digest", name)
		}
	}
}

func TestSingleScanBase(t *testing.T) {
	t.Parallel()
	cwd := filepath.FromSlash("/work/repo")
	cases := []struct {
		paths []string
		want  string
	}{
		{[]string{"infra"}, "infra"},
		{[]string{"./infra/prod/"}, "infra/prod"},
		{[]string{"infra", "infra/"}, "infra"},
		{[]string{filepath.FromSlash("/work/repo/infra")}, "infra"},
		{[]string{"."}, ""},
		{[]string{filepath.FromSlash("/work/repo")}, ""},
		{nil, ""},
		{[]string{"a", "b"}, ""},
		{[]string{"../other"}, ""},
		{[]string{filepath.FromSlash("/elsewhere/infra")}, ""},
	}
	for _, c := range cases {
		if got := SingleScanBase(cwd, c.paths); got != c.want {
			t.Errorf("SingleScanBase(%q) = %q, want %q", c.paths, got, c.want)
		}
	}
}
