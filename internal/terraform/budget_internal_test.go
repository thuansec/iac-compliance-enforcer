package terraform

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// budgetRoot writes files under a temp scan root and opens it.
func budgetRoot(t *testing.T, files map[string]string) *fsutil.Root {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func cost(t *testing.T, name, src string) int {
	t.Helper()
	n, err := lexCost(name, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A module's files are parsed while the scan's budget has room for each: at the budget both
// fit, one token less leaves the second file unparsed with a parse_limit warning.
func TestParseBudgetBoundary(t *testing.T) {
	t.Parallel()
	a, b := `resource "aws_s3_bucket" "a" {}`, `resource "aws_s3_bucket" "b" { bucket = "x" }`
	both := cost(t, "a.tf", a) + cost(t, "b.tf", b)
	for _, tc := range []struct {
		budget  int
		blocks  int
		limited bool
	}{{both + 1, 2, false}, {both, 2, false}, {both - 1, 1, true}} {
		r := budgetRoot(t, map[string]string{"a.tf": a, "b.tf": b})
		limits := DefaultLimits()
		limits.ParseBudget = NewParseBudget(tc.budget)
		m, err := ParseModule(context.Background(), r, Dir{Path: ".", Files: []string{"a.tf", "b.tf"}}, limits)
		if err != nil {
			t.Fatal(err)
		}
		limited := slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool {
			return d.Code == DiagParseLimit && d.File == "b.tf" && d.Severity == SeverityWarning
		})
		if len(m.Blocks) != tc.blocks || limited != tc.limited {
			t.Errorf("budget %d of %d: %d blocks, limited %v; want %d, %v", tc.budget, both, len(m.Blocks), limited, tc.blocks, tc.limited)
		}
	}
}

// One budget is shared by every ParseModule call with the same Limits, and JSON files count
// their bytes.
func TestParseBudgetIsSharedAcrossModules(t *testing.T) {
	t.Parallel()
	hclSrc, jsonSrc := `resource "aws_s3_bucket" "a" {}`, `{"resource": {"aws_s3_bucket": {"j": {}}}}`
	if got := cost(t, "x.tf.json", jsonSrc); got != len(jsonSrc) {
		t.Errorf("JSON cost %d, want its %d bytes", got, len(jsonSrc))
	}
	r := budgetRoot(t, map[string]string{"one/a.tf": hclSrc, "two/b.tf.json": jsonSrc})
	limits := DefaultLimits()
	limits.ParseBudget = NewParseBudget(cost(t, "a.tf", hclSrc) + len(jsonSrc) - 1)
	m1, err := ParseModule(context.Background(), r, Dir{Path: "one", Files: []string{"one/a.tf"}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := ParseModule(context.Background(), r, Dir{Path: "two", Files: []string{"two/b.tf.json"}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(m1.Blocks) != 1 || len(m2.Blocks) != 0 || !slices.ContainsFunc(m2.Diagnostics, func(d Diagnostic) bool {
		return d.Code == DiagParseLimit
	}) {
		t.Errorf("first module %d blocks, second %d blocks with %v", len(m1.Blocks), len(m2.Blocks), m2.Diagnostics)
	}
}

// DefaultLimits gives each scan a fresh budget of MaxScanTokens; a nil budget takes everything.
func TestDefaultParseBudget(t *testing.T) {
	t.Parallel()
	a, b := DefaultLimits(), DefaultLimits()
	if a.ParseBudget == nil || a.ParseBudget == b.ParseBudget || a.ParseBudget.size() != MaxScanTokens {
		t.Errorf("default budgets %p and %p of %d", a.ParseBudget, b.ParseBudget, a.ParseBudget.size())
	}
	var none *ParseBudget
	if !none.take(1 << 40) {
		t.Error("a nil budget refused")
	}
}

// EvaluateRoots draws every root from one budget: once the first root used it up, the second
// root's file is not parsed, and its warning is reported on that root.
func TestParseBudgetSpansRoots(t *testing.T) {
	t.Parallel()
	src := `resource "aws_s3_bucket" "a" {}`
	r := budgetRoot(t, map[string]string{"one/main.tf": src, "two/main.tf": src})
	limits := DefaultLimits()
	limits.ParseBudget = NewParseBudget(cost(t, "main.tf", src))
	d, err := Discover(t.Context(), r, limits)
	if err != nil {
		t.Fatal(err)
	}
	mods, err := ClassifyModules(t.Context(), r, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	results, err := EvaluateRoots(t.Context(), r, d, mods, VarOptions{}, limits, TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || len(results[0].Instances[0].Resources) != 1 || len(results[1].Instances[0].Resources) != 0 {
		t.Fatalf("roots: %d", len(results))
	}
	if !slices.ContainsFunc(results[1].Tree.Root.Module.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagParseLimit }) {
		t.Errorf("second root has no parse_limit: %v", results[1].Tree.Root.Module.Diagnostics)
	}
}

// TestKeptHeapPerBudgetToken: what a parsed module keeps (its syntax and its sources) per budget
// token stays under keptBytesPerToken for the worst shapes, so MaxScanTokens bounds the scan's
// kept trees at about 400 MB (ADR 0017).
func TestKeptHeapPerBudgetToken(t *testing.T) {
	const keptBytesPerToken = 140
	limit := int(DefaultLimits().MaxFileSize)
	shapes := map[string]string{
		"operator chain": "locals {\n  a = 1" + strings.Repeat("+1", limit/2-16) + "\n}\n",
		"list":           "locals {\n  a = [" + strings.Repeat("1,", limit/2-16) + "]\n}\n",
		"call arguments": "locals {\n  a = max(" + strings.Repeat("1,", limit/2-16) + "1)\n}\n",
		"long literal":   "locals {\n  a = \"" + strings.Repeat("x", limit-32) + "\"\n}\n",
		"long comment":   "# " + strings.Repeat("x", limit-8) + "\n",
		"realistic":      fill(limit, "resource \"aws_s3_bucket\" \"b%d\" {\n  bucket = \"name\"\n  tags = { Env = var.env }\n}\n"),
		"nested blocks":  "resource \"a\" \"b\" {\n" + strings.Repeat("b{}\n", limit/4-16) + "}\n",
		"json list":      `{"locals":{"a":[` + strings.Repeat("1,", limit/2-32) + `1]}}`,
	}
	for name, src := range shapes {
		file := "main.tf"
		if strings.HasPrefix(name, "json") {
			file = "main.tf.json"
		}
		r := budgetRoot(t, map[string]string{file: src})
		c := cost(t, file, src)
		limits := DefaultLimits()
		limits.ParseBudget = nil
		base := liveHeap()
		m, err := ParseModule(context.Background(), r, Dir{Path: ".", Files: []string{file}}, limits)
		if err != nil {
			t.Fatal(err)
		}
		memorySink = m
		kept := max(int64(liveHeap())-int64(base), 0)
		memorySink = nil
		perToken := kept / int64(c)
		t.Logf("%s: cost %d, kept %d MB, %d bytes per budget token", name, c, kept>>20, perToken)
		if perToken > keptBytesPerToken {
			t.Errorf("%s keeps %d bytes per budget token, want at most %d", name, perToken, keptBytesPerToken)
		}
	}
}

// A file of one long literal or one long comment has few tokens but keeps its bytes: its cost
// counts them, so a budget its token count alone would fit refuses it, and a refused file keeps
// no source.
func TestLongTokensAreCharged(t *testing.T) {
	t.Parallel()
	limit := int(DefaultLimits().MaxFileSize)
	for name, src := range map[string]string{
		"long literal": "locals {\n  a = \"" + strings.Repeat("x", limit-32) + "\"\n}\n",
		"long comment": "# " + strings.Repeat("x", limit-8) + "\n",
	} {
		tokens, _ := hclsyntax.LexConfig([]byte(src), "main.tf", hcl.InitialPos)
		r := budgetRoot(t, map[string]string{"main.tf": src})
		limits := DefaultLimits()
		limits.ParseBudget = NewParseBudget(len(tokens) * 100)
		m, err := ParseModule(context.Background(), r, Dir{Path: ".", Files: []string{"main.tf"}}, limits)
		if err != nil {
			t.Fatal(err)
		}
		refused := slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagParseLimit })
		if _, kept := m.src["main.tf"]; !refused || kept {
			t.Errorf("%s (%d tokens, cost %d): refused %v, source kept %v", name, len(tokens), cost(t, "main.tf", src), refused, kept)
		}
	}
}

// EvaluateRoots gives a scan without a budget a fresh one of MaxScanTokens: four 1 MiB operator
// chains cost about 1.08M budget tokens each, so the fourth root is refused.
func TestEvaluateRootsCreatesABudget(t *testing.T) {
	limit := int(DefaultLimits().MaxFileSize)
	src := "locals {\n  a = 1" + strings.Repeat("+1", limit/2-16) + "\n}\n"
	r := budgetRoot(t, map[string]string{"a/main.tf": src, "b/main.tf": src, "c/main.tf": src})
	if c := cost(t, "main.tf", src); 3*c <= MaxScanTokens {
		t.Fatalf("three files cost %d, within the budget %d", 3*c, MaxScanTokens)
	}
	limits := DefaultLimits()
	limits.ParseBudget = nil
	d, err := Discover(t.Context(), r, limits)
	if err != nil {
		t.Fatal(err)
	}
	mods, err := ClassifyModules(t.Context(), r, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	results, err := EvaluateRoots(t.Context(), r, d, mods, VarOptions{}, limits, TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, res := range results {
		if slices.ContainsFunc(res.Tree.Root.Module.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagParseLimit }) {
			refused++
		}
	}
	if refused != 1 {
		t.Errorf("%d roots refused, want the third", refused)
	}
}
