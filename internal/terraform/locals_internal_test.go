package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// parseLocalsModule parses one main.tf holding src.
func parseLocalsModule(t *testing.T, src string) *ParsedModule {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	m, err := ParseModule(context.Background(), r, Dir{Path: ".", Files: []string{"main.tf"}}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// stringVar is a variable holding a string of n bytes, which has size n+1.
func stringVar(n int) map[string]Variable {
	return map[string]Variable{"s": {Value: cty.StringVal(strings.Repeat("x", n))}}
}

func diagCodes(m *ParsedModule) []DiagCode {
	var out []DiagCode
	for _, d := range m.Diagnostics {
		out = append(out, d.Code)
	}
	return out
}

// nested is a value of the given depth: a leaf string inside depth-1 tuples.
func nested(depth int) cty.Value {
	v := cty.StringVal("x")
	for range depth - 1 {
		v = cty.TupleVal([]cty.Value{v})
	}
	return v
}

func TestValueSizeLimits(t *testing.T) {
	t.Parallel()
	obj := cty.ObjectVal(map[string]cty.Value{"ab": cty.StringVal("xyz"), "n": cty.NullVal(cty.String)})
	wide := make([]cty.Value, 1000)
	for i := range wide {
		wide[i] = cty.True
	}
	tests := []struct {
		name         string
		val          cty.Value
		limit, depth int
		want         int
		ok           bool
	}{
		// object (1) + "ab" (2) + "xyz" (1+3) + "n" (1) + null (1)
		{"object at limit", obj, 9, 4, 9, true},
		{"object above limit", obj, 8, 4, 0, false},
		{"string at limit", cty.StringVal("abc"), 4, 4, 4, true},
		{"string above limit", cty.StringVal("abcd"), 4, 4, 0, false},
		{"marked and unknown", cty.TupleVal([]cty.Value{cty.UnknownVal(cty.String).Mark(SensitiveMark)}), 2, 4, 2, true},
		// Depth counts the levels below the top value.
		{"depth at limit", nested(5), 100, 4, 6, true},
		{"depth above limit", nested(6), 100, 4, 0, false},
		// A wide value is refused before all of its elements are queued.
		{"wide", cty.ListVal(wide), 10, 4, 0, false},
	}
	for _, tt := range tests {
		got, ok := valueSize(tt.val, tt.limit, tt.depth)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("%s: valueSize = %d, %v; want %d, %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

func TestUnknownPathsLimits(t *testing.T) {
	t.Parallel()
	unknowns := func(n int) cty.Value {
		elems := make([]cty.Value, n)
		for i := range elems {
			elems[i] = cty.UnknownVal(cty.String)
		}
		return cty.TupleVal(elems)
	}
	if got := unknownPaths(unknowns(maxUnknownPaths)); len(got) != maxUnknownPaths {
		t.Errorf("at the path limit: got %d paths, want %d", len(got), maxUnknownPaths)
	}
	if got := unknownPaths(unknowns(maxUnknownPaths + 1)); len(got) != 1 || len(got[0]) != 0 {
		t.Errorf("above the path limit: got %d paths, want only the whole value", len(got))
	}
	// Steps: unknowns at depth d cost d steps each.
	deep := func(paths, depth int) cty.Value {
		elems := make([]cty.Value, paths)
		for i := range elems {
			v := cty.UnknownVal(cty.String)
			for range depth - 1 {
				v = cty.TupleVal([]cty.Value{v})
			}
			elems[i] = v
		}
		return cty.TupleVal(elems)
	}
	perPath := maxUnknownPathSteps / 512
	if got := unknownPaths(deep(512, perPath)); len(got) != 512 || len(got[511]) != perPath {
		t.Errorf("at the step limit: got %d paths, want 512 of %d steps", len(got), perPath)
	}
	if got := unknownPaths(deep(512, perPath+1)); len(got) != 1 || len(got[0]) != 0 {
		t.Errorf("above the step limit: got %d paths, want only the whole value", len(got))
	}
}

func TestLocalReferencesLimit(t *testing.T) {
	t.Parallel()
	s := &localState{safe: true, refs: []string{"b.x"}, deps: []string{"d"}}
	done := map[string]Local{"d": {References: []string{"a.x", "b.x"}}}
	refs, incomplete, capped := localReferences(s, done, nil, maxReferenceEntries-3)
	if fmt.Sprint(refs) != "[a.x b.x]" || incomplete || capped {
		t.Errorf("at the limit: %v, incomplete %v, capped %v; want [a.x b.x], complete", refs, incomplete, capped)
	}
	refs, incomplete, capped = localReferences(s, done, nil, maxReferenceEntries-2)
	if fmt.Sprint(refs) != "[b.x]" || !incomplete || !capped {
		t.Errorf("above the limit: %v, incomplete %v, capped %v; want only its own, incomplete", refs, incomplete, capped)
	}
}

// TestLocalValueSizeLimit: the estimate for `x = var.s` is its 5 source bytes plus the size of
// var.s (n+1), so the largest string that fits is maxLocalValueSize-6 bytes.
func TestLocalValueSizeLimit(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		n     int
		known bool
	}{{maxLocalValueSize - 7, true}, {maxLocalValueSize - 6, true}, {maxLocalValueSize - 5, false}} {
		m := parseLocalsModule(t, "locals {\n  x = var.s\n}\n")
		vars := stringVar(tt.n)
		vars["s"] = Variable{Value: vars["s"].Value.Mark(SensitiveMark)}
		locals, err := m.EvaluateLocals(context.Background(), vars)
		if err != nil {
			t.Fatal(err)
		}
		x := locals["x"].Value
		if x.IsKnown() != tt.known {
			t.Errorf("n=%d: known = %v, want %v", tt.n, x.IsKnown(), tt.known)
		}
		if !x.ContainsMarked() {
			t.Errorf("n=%d: the value lost its sensitive mark", tt.n)
		}
		wantDiags := fmt.Sprint([]DiagCode(nil))
		if !tt.known {
			wantDiags = fmt.Sprint([]DiagCode{DiagValueTooLarge})
		}
		if got := fmt.Sprint(diagCodes(m)); got != wantDiags {
			t.Errorf("n=%d: diagnostics %s, want %s", tt.n, got, wantDiags)
		}
	}
}

// TestLocalsTotalSizeLimit: locals that each fit stop being evaluated once together they would
// pass maxLocalsSize.
func TestLocalsTotalSizeLimit(t *testing.T) {
	t.Parallel()
	const n = maxLocalValueSize - 6 // each value has size n+1
	fits := maxLocalsSize / (n + 1)
	var b strings.Builder
	b.WriteString("locals {\n")
	for i := range fits + 1 {
		fmt.Fprintf(&b, "  x%03d = var.s\n", i)
	}
	b.WriteString("}\n")
	m := parseLocalsModule(t, b.String())
	locals, err := m.EvaluateLocals(context.Background(), stringVar(n))
	if err != nil {
		t.Fatal(err)
	}
	for i := range fits + 1 {
		name := fmt.Sprintf("x%03d", i)
		if want := i < fits; locals[name].Value.IsKnown() != want {
			t.Errorf("local.%s known = %v, want %v", name, !want, want)
		}
	}
	if got, want := fmt.Sprint(diagCodes(m)), fmt.Sprint([]DiagCode{DiagValueTooLarge}); got != want {
		t.Errorf("diagnostics %s, want %s", got, want)
	}
}
