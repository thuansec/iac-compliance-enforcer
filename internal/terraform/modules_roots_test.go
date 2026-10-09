package terraform_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

func evaluateRoots(ctx context.Context, t *testing.T, dir string) ([]terraform.RootResult, error) {
	t.Helper()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	limits := terraform.DefaultLimits()
	load := context.WithoutCancel(ctx)
	d, err := terraform.Discover(load, r, limits)
	if err != nil {
		t.Fatal(err)
	}
	mods, err := terraform.ClassifyModules(load, r, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	return terraform.EvaluateRoots(ctx, r, d, mods, terraform.VarOptions{}, limits, terraform.TreeOptions{})
}

// rootSummary lists each root as "dir" or "dir (orphan)" with its resources' addresses.
func rootSummary(results []terraform.RootResult) []string {
	var out []string
	for _, res := range results {
		line := res.Dir
		if res.Orphan {
			line += " (orphan)"
		}
		var addrs []string
		for _, inst := range res.Instances {
			for _, r := range inst.Resources {
				addrs = append(addrs, r.Address)
			}
		}
		out = append(out, fmt.Sprintf("%s: %v", line, addrs))
	}
	return out
}

func TestUninstantiatedChildrenAreScannedAsRoots(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `module "zero" {
  source = "./zero"
  count  = 0
}
module "empty" {
  source   = "./empty"
  for_each = {}
}
module "used" {
  source = "./used"
}
module "decoy" {
  source = "./good"
}
`,
		// An override file redirects module.decoy to ./evil, as Terraform would, so ./good is
		// uninstantiated.
		"main_override.tf":    "module \"decoy\" {\n  source = \"./evil\"\n}\n",
		"zero/main.tf":        "resource \"aws_s3_bucket\" \"z\" {}\n" + module("deep", "../deep"),
		"deep/main.tf":        `resource "aws_s3_bucket" "d" {}`,
		"empty/main.tf":       `resource "aws_s3_bucket" "e" {}`,
		"used/main.tf":        `resource "aws_s3_bucket" "u" {}`,
		"good/main.tf":        `resource "aws_s3_bucket" "g" {}`,
		"evil/main.tf":        `resource "aws_s3_bucket" "x" {}`,
		".hidden/mod/main.tf": `resource "aws_s3_bucket" "h" {}`,
		"other/main.tf":       "module \"h\" {\n  source = \"../.hidden/mod\"\n  count  = 0\n}\n",
	})
	results, err := evaluateRoots(context.Background(), t, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		". : [module.used.aws_s3_bucket.u module.decoy.aws_s3_bucket.x]",
		"other: []",
		".hidden/mod (orphan): [aws_s3_bucket.h]",
		"empty (orphan): [aws_s3_bucket.e]",
		"good (orphan): [aws_s3_bucket.g]",
		// ./deep is instantiated through the orphan ./zero, so it is not an orphan itself.
		"zero (orphan): [aws_s3_bucket.z module.deep.aws_s3_bucket.d]",
	}
	got := rootSummary(results)
	for i := range got {
		got[i] = fixRootDot(got[i])
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("roots (-want +got):\n%s", diff)
	}
	for _, res := range results {
		root := res.Instances[0].Module
		warned := slices.ContainsFunc(root.Diagnostics, func(d terraform.Diagnostic) bool {
			return d.Code == terraform.DiagUninstantiatedModule
		})
		if warned != res.Orphan {
			t.Errorf("%s: uninstantiated_module warning %v, orphan %v", res.Dir, warned, res.Orphan)
		}
	}
}

// fixRootDot writes the root "." as ". " so it sorts and reads apart from the others.
func fixRootDot(s string) string {
	if len(s) > 2 && s[:2] == ".:" {
		return ". :" + s[2:]
	}
	return s
}

// A child that a tree skipped for its budget has an instance and a module_work_limit warning:
// it is reported, so it is not scanned again as a root.
func TestSkippedChildrenAreNotOrphans(t *testing.T) {
	t.Parallel()
	// ./late's only call comes after ./c's instances used up the tree budget.
	dir := files(t, map[string]string{
		"main.tf":      fanOut(10, "./c") + module("late", "./late"),
		"c/main.tf":    heavyModule(200_000, 38),
		"late/main.tf": `resource "aws_s3_bucket" "l" {}`,
	})
	results, err := evaluateRoots(context.Background(), t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Orphan {
		t.Errorf("%d roots, want only the root", len(results))
	}
	late := instance(t, results[0].Instances, "module.late")
	if !late.Skipped {
		t.Error("module.late was evaluated; the test needs it skipped")
	}
}

func TestEvaluateRootsHonoursCancellation(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{"main.tf": "", "c/main.tf": ""})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := evaluateRoots(ctx, t, dir); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// Orphans that call each other in a cycle: the first by path is scanned as a root, and the
// other is instantiated through it.
func TestOrphanCyclesAreScannedOnce(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":   "module \"a\" {\n  source = \"./a\"\n  count  = 0\n}\n",
		"a/main.tf": "resource \"aws_s3_bucket\" \"a\" {}\n" + module("b", "../b"),
		"b/main.tf": "resource \"aws_s3_bucket\" \"b\" {}\n" + module("a", "../a"),
	})
	results, err := evaluateRoots(context.Background(), t, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".: []", "a (orphan): [aws_s3_bucket.a module.b.aws_s3_bucket.b]"}
	if diff := cmp.Diff(want, rootSummary(results)); diff != "" {
		t.Errorf("roots (-want +got):\n%s", diff)
	}
}

// Calls made inside hidden modules are not classified, but loaded trees reach them: a child
// such a call never instantiates is an orphan too.
func TestOrphansBelowHiddenModules(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		rootCall string
		want     []string
	}{
		"hidden orphan calling an orphan": {
			"module \"a\" {\n  source = \"./.h/a\"\n  count  = 0\n}\n",
			[]string{".: []", ".h/a (orphan): [aws_s3_bucket.a]", ".h/b (orphan): [aws_s3_bucket.b]"},
		},
		"instantiated hidden module calling an orphan": {
			module("a", "./.h/a"),
			[]string{".: [module.a.aws_s3_bucket.a]", ".h/b (orphan): [aws_s3_bucket.b]"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := files(t, map[string]string{
				"main.tf":      tc.rootCall,
				".h/a/main.tf": "resource \"aws_s3_bucket\" \"a\" {}\nmodule \"b\" {\n  source = \"../b\"\n  count  = 0\n}\n",
				".h/b/main.tf": `resource "aws_s3_bucket" "b" {}`,
			})
			results, err := evaluateRoots(context.Background(), t, dir)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, rootSummary(results)); diff != "" {
				t.Errorf("roots (-want +got):\n%s", diff)
			}
		})
	}
}

// When every orphan waits on another, the one scanned first is in the cycle: here b and c call
// each other and b calls a, so b goes first, and a is scanned once, through b.
func TestOrphanCycleFallbackPicksACycleMember(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":   "module \"b\" {\n  source = \"./b\"\n  count  = 0\n}\n",
		"a/main.tf": `resource "aws_s3_bucket" "a" {}`,
		"b/main.tf": "resource \"aws_s3_bucket\" \"b\" {}\n" + module("a", "../a") + module("c", "../c"),
		"c/main.tf": "resource \"aws_s3_bucket\" \"c\" {}\n" + module("b", "../b"),
	})
	results, err := evaluateRoots(context.Background(), t, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".: []", "b (orphan): [aws_s3_bucket.b module.a.aws_s3_bucket.a module.c.aws_s3_bucket.c]"}
	if diff := cmp.Diff(want, rootSummary(results)); diff != "" {
		t.Errorf("roots (-want +got):\n%s", diff)
	}
}

// Orphans never trust the module manifest: the pipeline prepared .terraform for its roots only.
func TestOrphansDoNotTrustTheManifest(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":                           "module \"o\" {\n  source = \"./o\"\n  count  = 0\n}\n",
		"o/main.tf":                         module("r", "acme/r/aws"),
		"o/.terraform/modules/r/main.tf":    `resource "aws_s3_bucket" "r" {}`,
		"o/.terraform/modules/modules.json": `{"Modules":[{"Key":"r","Source":"registry.terraform.io/acme/r/aws","Dir":".terraform/modules/r"}]}`,
	})
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	limits := terraform.DefaultLimits()
	d, err := terraform.Discover(context.Background(), r, limits)
	if err != nil {
		t.Fatal(err)
	}
	mods, err := terraform.ClassifyModules(context.Background(), r, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	results, err := terraform.EvaluateRoots(context.Background(), r, d, mods, terraform.VarOptions{}, limits,
		terraform.TreeOptions{TrustModuleManifest: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || !results[1].Orphan || results[1].Tree.Root.Calls[0].Unresolved != terraform.UnresolvedRemote {
		t.Errorf("orphan remote call: %+v", results[len(results)-1].Tree.Root.Calls)
	}
}
