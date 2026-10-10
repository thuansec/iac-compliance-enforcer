package terraform

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// evalManyLocals evaluates n locals `a<i> = expr` with var.c.l a list of size elements.
func evalManyLocals(t *testing.T, n int, expr string, size int) (*ParsedModule, map[string]Local) {
	t.Helper()
	var b strings.Builder
	b.WriteString("locals {\n")
	for i := range n {
		fmt.Fprintf(&b, "  a%d = %s\n", i, expr)
	}
	b.WriteString("}\n")
	m := parseLocalsModule(t, b.String())
	list := cty.ListVal(slices.Repeat([]cty.Value{cty.True}, size))
	vars := map[string]Variable{"c": {Name: "c", Value: cty.ObjectVal(map[string]cty.Value{"l": list})}}
	locals, err := m.EvaluateLocals(context.Background(), vars)
	if err != nil {
		t.Fatal(err)
	}
	return m, locals
}

// Calls and operators walk their arguments in full inside cty, before iace can refuse them, so a
// local that calls or compares a large input is charged that input up front: 3,000 locals over a
// 120,000-element list took about 140 s (length) and 44 s (!= null) per thousand when each walked
// it for free (T-0114a). Now the module's function work bounds how many are evaluated.
func TestWalkingLocalsAreCharged(t *testing.T) {
	t.Parallel()
	for _, expr := range []string{"var.c.l != null", "length(var.c.l)"} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			m, locals := evalManyLocals(t, 3000, expr, 120_000)
			known := 0
			for _, l := range locals {
				if l.Value.IsKnown() {
					known++
				}
			}
			// Each evaluated local is charged at least argumentWalkWork × the list's size.
			if limit := maxFunctionWork/(argumentWalkWork*120_000) + 1; known == 0 || known > limit {
				t.Errorf("%d of 3000 locals evaluated, want 1 to %d", known, limit)
			}
			if !slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagFunctionLimit }) {
				t.Error("no function_limit diagnostic for the locals over the limit")
			}
		})
	}
}

// Ordinary configurations are unaffected: 200 locals calling and comparing a 1,000-element list
// all evaluate, and a local that only refers to a large value (no call, no operator) is not
// charged for walking it.
func TestOrdinaryLocalsAreNotLimited(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		n, size int
		expr    string
	}{
		"calls":      {200, 1000, "length(var.c.l) > 0"},
		"references": {30, 120_000, "[var.c.l]"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, locals := evalManyLocals(t, tc.n, tc.expr, tc.size)
			for i := range tc.n {
				if v := locals[fmt.Sprintf("a%d", i)].Value; !v.IsWhollyKnown() {
					t.Fatalf("a%d = %#v, diagnostics %v; want it evaluated", i, v, m.Diagnostics)
				}
			}
		})
	}
}

// A walking local is charged exactly argumentWalkWork × the size of its inputs, after measuring
// the path to them (ADR 0025: the measurement is charged too): it is evaluated when that fits the
// work left, and unknown with function_limit one unit short.
func TestWalkingLocalChargeIsExact(t *testing.T) {
	t.Parallel()
	list := cty.ListVal(slices.Repeat([]cty.Value{cty.True}, 10))
	size, _ := valueSize(list, maxFunctionWork, maxNesting)
	cost := size + argumentWalkWork*size // measuring var.c.l, then walking it
	vars := map[string]Variable{"c": {Name: "c", Value: cty.ObjectVal(map[string]cty.Value{"l": list})}}
	for name, tc := range map[string]struct {
		left  int
		known bool
	}{
		"below": {cost + 1, true},
		"at":    {cost, true},
		"above": {cost - 1, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := parseLocalsModule(t, "locals {\n  v = var.c.l != null\n}\n")
			m.fnWork = maxFunctionWork - tc.left
			locals, err := m.EvaluateLocals(context.Background(), vars)
			if err != nil {
				t.Fatal(err)
			}
			if got := locals["v"].Value.IsKnown(); got != tc.known {
				t.Errorf("known %v, want %v: %v", got, tc.known, m.Diagnostics)
			}
			limited := slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Code == DiagFunctionLimit })
			if limited == tc.known {
				t.Errorf("function_limit %v, want %v", limited, !tc.known)
			}
		})
	}
}

// For expressions and .tf.json expressions count as walking their inputs.
func TestWalksArguments(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		files map[string]string
		walks bool
	}{
		"reference": {map[string]string{"main.tf": "locals {\n  v = [var.c.l]\n}\n"}, false},
		"operator":  {map[string]string{"main.tf": "locals {\n  v = var.c.l != null\n}\n"}, true},
		"for":       {map[string]string{"main.tf": "locals {\n  v = [for x in var.c.l : x]\n}\n"}, true},
		"json":      {map[string]string{"main.tf.json": `{"locals": {"v": "${var.c.l}"}}`}, true},
	} {
		m := parseFilesModule(t, tc.files)
		states, _ := m.declareLocals()
		if got := walksArguments(states["v"].attr.Expr); got != tc.walks {
			t.Errorf("%s: walks %v, want %v", name, got, tc.walks)
		}
	}
}
