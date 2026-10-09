package terraform_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

func loadTree(t *testing.T, dir, rootDir string) *terraform.ModuleTree {
	t.Helper()
	tree, err := loadTreeErr(context.Background(), t, dir, rootDir)
	if err != nil {
		t.Fatalf("LoadModuleTree: %v", err)
	}
	return tree
}

func loadTreeErr(ctx context.Context, t *testing.T, dir, rootDir string) (*terraform.ModuleTree, error) {
	t.Helper()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	limits := terraform.DefaultLimits()
	// Discovery runs even when ctx is cancelled, so only LoadModuleTree sees the cancellation.
	d, err := terraform.Discover(context.WithoutCancel(ctx), r, limits)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return terraform.LoadModuleTree(ctx, r, d, rootDir, limits)
}

// flatten lists every call of the tree depth first as "address dir" or "address !reason".
func flatten(n *terraform.ModuleNode) []string {
	var out []string
	for _, c := range n.Calls {
		if c.Child == nil {
			out = append(out, c.Address+" !"+string(c.Unresolved))
			continue
		}
		out = append(out, c.Address+" "+c.Child.Dir)
		out = append(out, flatten(c.Child)...)
	}
	return out
}

// moduleDiags returns the diagnostics with code of every module in the tree, deduplicated, as
// "file:line summary".
func moduleDiags(tree *terraform.ModuleTree, code terraform.DiagCode) []string {
	seen := map[*terraform.ParsedModule]bool{}
	var out []string
	var walk func(n *terraform.ModuleNode)
	walk = func(n *terraform.ModuleNode) {
		if !seen[n.Module] {
			seen[n.Module] = true
			for _, d := range n.Module.Diagnostics {
				if d.Code == code {
					out = append(out, fmt.Sprintf("%s:%d %s %s", d.File, d.Line, d.Severity, d.Summary))
				}
			}
		}
		for _, c := range n.Calls {
			if c.Child != nil {
				walk(c.Child)
			}
		}
	}
	walk(tree.Root)
	return out
}

func TestLoadModuleTreeResolvesLocalCalls(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": module("net", "./modules/net") +
			"module \"consul\" {\n  source  = \"hashicorp/consul/aws\"\n  version = \"0.1.0\"\n}\n" +
			"module \"dyn\" {\n  source = var.src\n}\n" +
			"module \"nosrc\" {\n}\n" +
			module("escape", "../outside") +
			module("missing", "./nope") +
			module("file", "./modules/net/main.tf") +
			module("hidden", "./.modules/x"),
		"modules/net/main.tf":     module("sub", "./sub") + module("sub2", `.\\sub`),
		"modules/net/sub/main.tf": `resource "aws_vpc" "v" {}`,
		".modules/x/main.tf":      `resource "aws_s3_bucket" "b" {}`,
	})
	tree := loadTree(t, dir, ".")
	want := []string{
		"module.net modules/net",
		"module.net.module.sub modules/net/sub",
		"module.net.module.sub2 modules/net/sub",
		"module.consul !remote_source",
		"module.dyn !source_not_literal",
		"module.nosrc !missing_source",
		"module.escape !outside_root",
		"module.missing !not_found",
		"module.file !not_found",
		"module.hidden .modules/x",
	}
	if diff := cmp.Diff(want, flatten(tree.Root)); diff != "" {
		t.Errorf("tree (-want +got):\n%s", diff)
	}
	if tree.Root.Dir != "." || tree.Root.Address != "" || tree.Root.Depth != 0 {
		t.Errorf("root = %q %q %d", tree.Root.Dir, tree.Root.Address, tree.Root.Depth)
	}

	consul := tree.Root.Calls[1]
	if consul.Name != "consul" || consul.Source != "hashicorp/consul/aws" || consul.Version != "0.1.0" ||
		consul.File != "main.tf" || consul.DefRange.Start.Line != 4 || consul.Range.End.Line != 7 {
		t.Errorf("consul call = %+v", consul)
	}
	net := tree.Root.Calls[0].Child
	if net.Depth != 1 || len(net.Module.Blocks) != 2 {
		t.Errorf("net node: depth %d, %d blocks", net.Depth, len(net.Module.Blocks))
	}
	sub, sub2 := net.Calls[0].Child, net.Calls[1].Child
	if sub.Module != sub2.Module {
		t.Error("a directory called twice is parsed twice, want one shared parse")
	}
	if hidden := tree.Root.Calls[7].Child; len(hidden.Module.Blocks) != 1 {
		t.Errorf("hidden child has %d blocks, want 1", len(hidden.Module.Blocks))
	}

	wantDiags := []string{
		"main.tf:5 warning Module not resolved",
		"main.tf:9 warning Module not resolved",
		"main.tf:11 warning Module not resolved",
		"main.tf:14 warning Module not resolved",
		"main.tf:17 warning Module not resolved",
		"main.tf:20 warning Module not resolved",
	}
	if diff := cmp.Diff(wantDiags, moduleDiags(tree, terraform.DiagModuleUnresolved)); diff != "" {
		t.Errorf("module_unresolved diagnostics (-want +got):\n%s", diff)
	}
}

func TestLoadModuleTreeFromNestedRoot(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"envs/prod/main.tf":   module("net", "../../modules/net") + module("up", "../../../x"),
		"modules/net/main.tf": `resource "aws_vpc" "v" {}`,
	})
	tree := loadTree(t, dir, "envs/prod")
	want := []string{"module.net modules/net", "module.up !outside_root"}
	if diff := cmp.Diff(want, flatten(tree.Root)); diff != "" {
		t.Errorf("tree (-want +got):\n%s", diff)
	}
}

func TestLoadModuleTreeDetectsCycles(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":   module("self", "./") + module("a", "./a"),
		"a/main.tf": module("b", "../b"),
		"b/main.tf": module("a", "../a") + module("root", "../"),
	})
	tree := loadTree(t, dir, ".")
	want := []string{
		"module.self !cycle",
		"module.a a",
		"module.a.module.b b",
		"module.a.module.b.module.a !cycle",
		"module.a.module.b.module.root !cycle",
	}
	if diff := cmp.Diff(want, flatten(tree.Root)); diff != "" {
		t.Errorf("tree (-want +got):\n%s", diff)
	}
}

// moduleChain returns files for a root calling m1, m1 calling m2, …, down to mN.
func moduleChain(n int) map[string]string {
	fs := map[string]string{"main.tf": module("m1", "./m1")}
	for i := 1; i <= n; i++ {
		body := `resource "aws_vpc" "v" {}`
		if i < n {
			body = module(fmt.Sprintf("m%d", i+1), fmt.Sprintf("../m%d", i+1))
		}
		fs[fmt.Sprintf("m%d/main.tf", i)] = body
	}
	return fs
}

func TestLoadModuleTreeDepthLimit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		levels     int
		unresolved bool
	}{{31, false}, {32, false}, {33, true}} {
		t.Run(fmt.Sprint(tc.levels), func(t *testing.T) {
			t.Parallel()
			tree := loadTree(t, files(t, moduleChain(tc.levels)), ".")
			got := flatten(tree.Root)
			last := got[len(got)-1]
			if tc.unresolved {
				if len(got) != 33 || !strings.HasSuffix(last, " !depth_limit") {
					t.Errorf("%d calls, last %q; want 33 with the last past the depth limit", len(got), last)
				}
				return
			}
			if len(got) != tc.levels || strings.Contains(last, "!") {
				t.Errorf("%d calls, last %q; want %d resolved", len(got), last, tc.levels)
			}
		})
	}
}

func TestLoadModuleTreeCallLimit(t *testing.T) {
	t.Parallel()
	calls := func(n int) string {
		var b strings.Builder
		for i := range n {
			b.WriteString(module(fmt.Sprintf("c%d", i), "./c"))
		}
		return b.String()
	}
	for _, tc := range []struct {
		calls, unresolved int
	}{{terraform.MaxModuleCalls - 1, 0}, {terraform.MaxModuleCalls, 0}, {terraform.MaxModuleCalls + 1, 1}} {
		t.Run(fmt.Sprint(tc.calls), func(t *testing.T) {
			t.Parallel()
			tree := loadTree(t, files(t, map[string]string{
				"main.tf":   calls(tc.calls),
				"c/main.tf": `resource "aws_vpc" "v" {}`,
			}), ".")
			got := flatten(tree.Root)
			_, n, _ := countCalls(got)
			if len(got) != tc.calls || n != tc.unresolved || tree.Truncated != (n > 0) {
				t.Errorf("%d calls with %d over the limit, truncated %v; want %d with %d",
					len(got), n, tree.Truncated, tc.calls, tc.unresolved)
			}
		})
	}
}

// countCalls returns the calls of a flattened tree that are resolved, over the call limit, and
// unresolved for another reason.
func countCalls(calls []string) (resolved, limited, other int) {
	for _, s := range calls {
		switch {
		case strings.HasSuffix(s, " !call_limit"):
			limited++
		case strings.Contains(s, "!"):
			other++
		default:
			resolved++
		}
	}
	return resolved, limited, other
}

// A fan-out of two calls per level, 30 levels deep, would be 2^31 nodes: the call limit stops it.
func TestLoadModuleTreeFanOutStopsAtCallLimit(t *testing.T) {
	t.Parallel()
	fs := map[string]string{"main.tf": module("a", "./l1") + module("b", "./l1")}
	for i := 1; i <= 30; i++ {
		next := fmt.Sprintf("../l%d", i+1)
		fs[fmt.Sprintf("l%d/main.tf", i)] = module("a", next) + module("b", next)
	}
	fs["l31/main.tf"] = `resource "aws_vpc" "v" {}`
	tree := loadTree(t, files(t, fs), ".")
	resolved, limited, other := countCalls(flatten(tree.Root))
	if resolved != terraform.MaxModuleCalls || limited != 1 || other != 0 || !tree.Truncated {
		t.Errorf("%d resolved, %d over the limit, %d other, truncated %v; want %d, 1, 0, true",
			resolved, limited, other, tree.Truncated, terraform.MaxModuleCalls)
	}
	if got := moduleDiags(tree, terraform.DiagModuleUnresolved); len(got) != 1 {
		t.Errorf("module_unresolved = %v, want one warning for the call limit", got)
	}
}

// Unresolved calls count toward the limit too: many calls to a module holding many unresolved
// module blocks would otherwise build calls × blocks entries (T-0107a review: 20M calls, 13.8 GiB).
func TestLoadModuleTreeCountsUnresolvedCalls(t *testing.T) {
	t.Parallel()
	var root, child strings.Builder
	for i := range 500 {
		root.WriteString(module(fmt.Sprintf("c%d", i), "./c"))
	}
	for i := range 2_000 {
		fmt.Fprintf(&child, "module \"m%d\" {\n}\n", i)
	}
	tree := loadTree(t, files(t, map[string]string{"main.tf": root.String(), "c/main.tf": child.String()}), ".")
	calls := flatten(tree.Root)
	resolved, limited, other := countCalls(calls)
	if len(calls) != terraform.MaxModuleCalls+1 || limited != 1 || !tree.Truncated {
		t.Errorf("%d calls (%d resolved, %d over the limit, %d other), truncated %v; want %d calls and 1 over the limit",
			len(calls), resolved, limited, other, tree.Truncated, terraform.MaxModuleCalls+1)
	}
	// The child's 2,000 missing sources are reported once, by its one parse.
	if got := len(moduleDiags(tree, terraform.DiagModuleUnresolved)); got != 2_001 {
		t.Errorf("%d module_unresolved warnings, want 2,001", got)
	}
}

func TestLoadModuleTreeRejectsDuplicateAndInvalidNames(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":   module("a", "./a") + module("a", "./b") + module("not valid", "./a"),
		"a/main.tf": "",
		"b/main.tf": "",
	})
	tree := loadTree(t, dir, ".")
	if diff := cmp.Diff([]string{"module.a a"}, flatten(tree.Root)); diff != "" {
		t.Errorf("tree (-want +got):\n%s", diff)
	}
	want := []string{"main.tf:4 error Duplicate module call"}
	if diff := cmp.Diff(want, moduleDiags(tree, terraform.DiagDuplicateModule)); diff != "" {
		t.Errorf("duplicate_module (-want +got):\n%s", diff)
	}
	want = []string{"main.tf:7 error Invalid module name"}
	if diff := cmp.Diff(want, moduleDiags(tree, terraform.DiagInvalidModuleName)); diff != "" {
		t.Errorf("invalid_module_name (-want +got):\n%s", diff)
	}
	if !tree.Root.Module.HasErrors() {
		t.Error("root module has no errors")
	}
}

func TestLoadModuleTreeJSONCalls(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf.json": `{"module": {"net": {"source": "./net", "version": "1.2.3"}, "dyn": {"source": "${var.s}"}, ` +
			`"tpl": {"source": "./${var.d}"}}}`,
		"net/main.tf":      `resource "aws_vpc" "v" {}`,
		"${var.d}/main.tf": `resource "aws_vpc" "v" {}`,
	})
	tree := loadTree(t, dir, ".")
	// Terraform decodes a JSON source without an evaluation context, so it is the literal
	// string, template sequences included.
	want := []string{"module.net net", "module.dyn !remote_source", "module.tpl ${var.d}"}
	if diff := cmp.Diff(want, flatten(tree.Root)); diff != "" {
		t.Errorf("tree (-want +got):\n%s", diff)
	}
	if v := tree.Root.Calls[0].Version; v != "1.2.3" {
		t.Errorf("net version = %q", v)
	}
	wantModules := &terraform.Modules{Roots: []string{"."}, Children: []string{"${var.d}", "net"}}
	if diff := cmp.Diff(wantModules, classify(t, dir)); diff != "" {
		t.Errorf("ClassifyModules (-want +got):\n%s", diff)
	}
}

func TestLoadModuleTreeFailsClosed(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{"main.tf": module("a", "./a"), "a/main.tf": ""})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := loadTreeErr(ctx, t, dir, "."); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err = %v, want context.Canceled", err)
	}
	if _, err := loadTreeErr(context.Background(), t, dir, "missing"); err == nil {
		t.Error("a root directory that was not discovered loaded without an error")
	}
}

// Listing hidden directories shares discovery's file budget, records the limit once, and never
// lists a directory discovery walked again (its skips are discovery's).
func TestLoadModuleTreeSharesTheFileBudget(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":  module("m", "./.m") + module("n", "./.n") + module("big", "./big"),
		".m/a.tf":  "",
		".m/b.tf":  "",
		".n/c.tf":  "",
		"big/x.tf": strings.Repeat("#", 200),
	})
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	limits := terraform.Limits{MaxFileSize: 150, MaxFiles: 3}
	d, err := terraform.Discover(context.Background(), r, limits)
	if err != nil {
		t.Fatal(err)
	}
	if d.Entries != 2 { // main.tf and the skipped big/x.tf
		t.Fatalf("discovery counted %d entries, want 2", d.Entries)
	}
	tree, err := terraform.LoadModuleTree(context.Background(), r, d, ".", limits)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"module.m .m", "module.n .n", "module.big big"}, flatten(tree.Root)); diff != "" {
		t.Errorf("tree (-want +got):\n%s", diff)
	}
	var skipped []string
	for _, s := range tree.Skipped {
		skipped = append(skipped, s.Path+" "+string(s.Reason))
	}
	if diff := cmp.Diff([]string{".m/b.tf file_limit"}, skipped); diff != "" {
		t.Errorf("Skipped (-want +got):\n%s", diff)
	}
	m, n := tree.Root.Calls[0].Child.Module, tree.Root.Calls[1].Child.Module
	if len(m.Blocks) != 0 || len(n.Blocks) != 0 {
		t.Errorf("hidden modules hold %d and %d blocks, want empty files only", len(m.Blocks), len(n.Blocks))
	}
}
