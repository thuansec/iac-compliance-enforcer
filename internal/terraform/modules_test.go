package terraform_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// files creates files with the given content under a temp dir.
func files(t *testing.T, contents map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range contents {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func module(name, source string) string {
	return "module \"" + name + "\" {\n  source = \"" + source + "\"\n}\n"
}

func classify(t *testing.T, dir string) *terraform.Modules {
	t.Helper()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	limits := terraform.DefaultLimits()
	d, err := terraform.Discover(context.Background(), r, limits)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m, err := terraform.ClassifyModules(context.Background(), r, d, limits)
	if err != nil {
		t.Fatalf("ClassifyModules: %v", err)
	}
	return m
}

func TestClassifyModules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		files map[string]string
		want  *terraform.Modules
	}{
		{
			name:  "single root without modules",
			files: map[string]string{"main.tf": `resource "aws_s3_bucket" "b" {}`},
			want:  &terraform.Modules{Roots: []string{"."}},
		},
		{
			name: "root calling a local child",
			files: map[string]string{
				"main.tf":             module("net", "./modules/net"),
				"modules/net/main.tf": `resource "aws_vpc" "v" {}`,
			},
			want: &terraform.Modules{Roots: []string{"."}, Children: []string{"modules/net"}},
		},
		{
			name: "nested roots sharing a child",
			files: map[string]string{
				"envs/prod/main.tf":       module("net", "../../modules/net"),
				"envs/dev/main.tf":        module("net", "../../modules/net/"),
				"envs/prod/extra/main.tf": `resource "aws_s3_bucket" "b" {}`,
				"modules/net/main.tf":     module("sub", "./sub"),
				"modules/net/sub/main.tf": `resource "aws_subnet" "s" {}`,
			},
			want: &terraform.Modules{
				Roots:    []string{"envs/dev", "envs/prod", "envs/prod/extra"},
				Children: []string{"modules/net", "modules/net/sub"},
			},
		},
		{
			name:  "a module calling itself is still a root",
			files: map[string]string{"main.tf": module("self", "./")},
			want:  &terraform.Modules{Roots: []string{"."}},
		},
		{
			name: "a call cycle without a root promotes its first directory",
			files: map[string]string{
				"a/main.tf":   module("b", "../b"),
				"b/main.tf":   module("a", "../a"),
				"b/c/main.tf": `resource "aws_vpc" "v" {}`,
			},
			want: &terraform.Modules{Roots: []string{"a", "b/c"}, Children: []string{"b"}},
		},
		{
			name: "a call cycle below a root stays children",
			files: map[string]string{
				"main.tf":   module("a", "./a"),
				"a/main.tf": module("b", "../b"),
				"b/main.tf": module("a", "../a"),
			},
			want: &terraform.Modules{Roots: []string{"."}, Children: []string{"a", "b"}},
		},
		{
			name: "json syntax module call",
			files: map[string]string{
				"main.tf.json":    `{"module": {"net": {"source": "./net"}}}`,
				"net/main.tf":     `resource "aws_vpc" "v" {}`,
				"other/main.tf":   `resource "aws_vpc" "v" {}`,
				"third/main.tf":   `resource "aws_vpc" "v" {}`,
				"other/vars.json": `{"module": {"x": {"source": "../third"}}}`, // not a Terraform file
			},
			want: &terraform.Modules{Roots: []string{".", "other", "third"}, Children: []string{"net"}},
		},
		{
			name: "module in a hidden directory",
			files: map[string]string{
				"main.tf":            module("x", "./.modules/x"),
				".modules/x/main.tf": `resource "aws_vpc" "v" {}`,
			},
			want: &terraform.Modules{Roots: []string{"."}, Children: []string{".modules/x"}},
		},
		{
			name: "sources that do not name a local directory inside the root are ignored",
			files: map[string]string{
				"main.tf": module("escape", "../outside") +
					module("deep", "./a/../../../outside") +
					module("registry", "terraform-aws-modules/vpc/aws") +
					module("git", "git::https://example.com/net.git") +
					module("missing", "./missing") +
					module("file", "./notes.txt") +
					"module \"dynamic\" {\n  source = var.src\n}\n" +
					"module \"nosource\" {}\n",
				"notes.txt": "not a module",
			},
			want: &terraform.Modules{Roots: []string{"."}},
		},
		{
			name: "a file with syntax errors still yields its module calls",
			files: map[string]string{
				"main.tf":     module("net", "./net") + "resource \"broken\" {\n",
				"net/main.tf": `resource "aws_vpc" "v" {}`,
			},
			want: &terraform.Modules{Roots: []string{"."}, Children: []string{"net"}},
		},
		{
			name:  "empty scan root",
			files: map[string]string{},
			want:  &terraform.Modules{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classify(t, files(t, tc.files))
			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreFields(terraform.Modules{}, "CalledBy")); diff != "" {
				t.Errorf("ClassifyModules (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClassifyModulesFailsWhenAFileChanged(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{"main.tf": module("net", "./net")})
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	limits := terraform.DefaultLimits()
	d, err := terraform.Discover(context.Background(), r, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "main.tf")); err != nil {
		t.Fatal(err)
	}
	if _, err := terraform.ClassifyModules(context.Background(), r, d, limits); err == nil {
		t.Error("ClassifyModules succeeded after a discovered file disappeared, want an error")
	}
}

func TestClassifyModulesHonoursCancellation(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{"main.tf": ""})
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	d, err := terraform.Discover(context.Background(), r, terraform.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := terraform.ClassifyModules(ctx, r, d, terraform.DefaultLimits()); err == nil {
		t.Error("ClassifyModules with a cancelled context succeeded, want an error")
	}
}

// CalledBy lists each child's local callers, override files included, without duplicates.
func TestClassifyModulesRecordsCallers(t *testing.T) {
	t.Parallel()
	m := classify(t, files(t, map[string]string{
		"main.tf":          module("a", "./a") + module("a2", "./a"),
		"main_override.tf": module("a", "./b"),
		"a/main.tf":        module("b", "../b"),
		"b/main.tf":        module("a", "../a"),
	}))
	want := map[string][]string{"a": {".", "b"}, "b": {".", "a"}}
	if diff := cmp.Diff(want, m.CalledBy); diff != "" {
		t.Errorf("CalledBy (-want +got):\n%s", diff)
	}
}
