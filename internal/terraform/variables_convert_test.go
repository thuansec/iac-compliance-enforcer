package terraform_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// tupleSource is an HCL tuple of n strings ending with a bool, so its element types differ.
func tupleSource(n int) string {
	return "[" + strings.Repeat(`"a", `, n-1) + "true]"
}

// nestedSource is an HCL tuple of n tuples of strings, of lengths 1,024, 1,023, ...
func nestedSource(n int) string {
	inner := make([]string, n)
	for i := range inner {
		inner[i] = "[" + strings.TrimSuffix(strings.Repeat(`"a", `, 1024-i), ", ") + "]"
	}
	return "[" + strings.Join(inner, ", ") + "]"
}

// mixedSource is an HCL tuple of n tuples of 64 numbers and a string: cty sorts the mixed
// types comparing the tuples element by element, then fails to convert (T-0114d review: 13 s).
func mixedSource(n int) string {
	inner := "[" + strings.TrimSuffix(strings.Repeat("1, ", 64), ", ") + "]"
	return "[" + strings.Repeat(inner+", ", n) + "\"x\"]"
}

// objectSource is an HCL object of n string attributes.
func objectSource(n int) string {
	var b strings.Builder
	b.WriteString("{\n")
	for i := range n {
		fmt.Fprintf(&b, "  k%d = \"a\"\n", i)
	}
	b.WriteString("}")
	return b.String()
}

// Converting a large tuple or object to a variable's collection type unifies its element types
// in quadratic time: a list(any) default over 20,000 elements took 4.7 s (T-0114c review). The
// conversion is charged first, from a default, a tfvars file, a --var flag or a module input;
// over the limit the variable is unknown with value_too_large (T-0114d).
func TestVariableConversionsAreBounded(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		files map[string]string
		opts  terraform.VarOptions
		dir   string
		known bool
	}{
		"small default": {files: map[string]string{
			"main.tf": "variable \"t\" {\n  type    = list(any)\n  default = " + tupleSource(2_000) + "\n}\n",
		}, known: true},
		"large default": {files: map[string]string{
			"main.tf": "variable \"t\" {\n  type    = list(any)\n  default = " + tupleSource(40_000) + "\n}\n",
		}},
		"large string list default": {files: map[string]string{
			"main.tf": "variable \"t\" {\n  type    = list(string)\n  default = " + tupleSource(40_000) + "\n}\n",
		}},
		// cty converts these two without unifying; the estimate over-counts them (T-0114g).
		"large map default, over-counted": {files: map[string]string{
			"main.tf": "variable \"t\" {\n  type    = map(string)\n  default = " + objectSource(20_000) + "\n}\n",
		}},
		"large optional default": {files: map[string]string{
			"main.tf": "variable \"t\" {\n  type    = list(object({ a = optional(string, \"d\") }))\n  default = [" +
				strings.Repeat("{}, ", 30_000) + "{ a = \"x\" }]\n}\n",
		}},
		"nested tuples default": {files: map[string]string{
			"main.tf": "variable \"t\" {\n  type    = list(any)\n  default = " + nestedSource(36) + "\n}\n",
		}},
		"mixed tuples and a string into list(any)": {files: map[string]string{
			"main.tf": "variable \"t\" {\n  type    = list(any)\n  default = " + mixedSource(4_096) + "\n}\n",
		}},
		"mixed tuples and a string into set(any)": {files: map[string]string{
			"main.tf": "variable \"t\" {\n  type    = set(any)\n  default = " + mixedSource(4_096) + "\n}\n",
		}},
		"large tfvars, over-counted": {files: map[string]string{
			"main.tf":    "variable \"t\" {\n  type = set(string)\n}\n",
			"big.tfvars": "t = " + tupleSource(40_000) + "\n",
		}, opts: terraform.VarOptions{VarFiles: []string{"big.tfvars"}}},
		"large --var": {files: map[string]string{
			"main.tf": "variable \"t\" {\n  type = list(string)\n}\n",
		}, opts: terraform.VarOptions{Vars: []string{"t=" + tupleSource(40_000)}}},
		"small --var": {files: map[string]string{
			"main.tf": "variable \"t\" {\n  type = list(string)\n}\n",
		}, opts: terraform.VarOptions{Vars: []string{"t=" + tupleSource(2_000)}}, known: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, vars, elapsed := timedEvalVars(t, tc.files, tc.opts)
			// Well under a second; converting took 4.7 to 25 s more.
			if elapsed > 3*time.Second*raceSlowdown {
				t.Errorf("evaluating the variables took %v", elapsed)
			}
			v := vars["t"].Value
			if v.IsKnown() != tc.known {
				t.Fatalf("value known %v, want %v: %v", v.IsKnown(), tc.known, codes(m))
			}
			tooLarge := slices.ContainsFunc(m.Diagnostics, func(d terraform.Diagnostic) bool {
				return d.Code == terraform.DiagValueTooLarge
			})
			if tooLarge == tc.known {
				t.Errorf("value_too_large reported = %v, want %v: %v", tooLarge, !tc.known, codes(m))
			}
			if tc.known && !v.Type().IsCollectionType() {
				t.Errorf("value of type %s, not converted", v.Type().FriendlyName())
			}
			if !tc.known && !v.Type().IsCollectionType() {
				t.Errorf("unknown of type %s, want the declared type", v.Type().FriendlyName())
			}
		})
	}
}

// A module input is converted to the child's variable type, charged in the child.
func TestModuleInputConversionsAreBounded(t *testing.T) {
	t.Parallel()
	for n, known := range map[int]bool{2_000: true, 40_000: false} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			dir := files(t, map[string]string{
				"main.tf":     "module \"net\" {\n  source = \"./net\"\n  t      = " + tupleSource(n) + "\n}\n",
				"net/main.tf": "variable \"t\" {\n  type = list(string)\n}\n",
			})
			start := time.Now()
			vars, child, _ := childVariables(t, dir, "net")
			// Under a second; converting took 14 s more.
			if elapsed := time.Since(start); elapsed > 5*time.Second*raceSlowdown {
				t.Errorf("took %v", elapsed)
			}
			if got := vars["t"].Value.IsKnown(); got != known {
				t.Fatalf("known = %v, want %v: %v", got, known, diagLines(child))
			}
			tooLarge := slices.ContainsFunc(child.Diagnostics, func(d terraform.Diagnostic) bool {
				return d.Code == terraform.DiagValueTooLarge
			})
			if tooLarge == known {
				t.Errorf("value_too_large reported = %v, want %v: %v", tooLarge, !known, diagLines(child))
			}
		})
	}
}

// timedEvalVars parses a module of contents and evaluates its variables, returning how long the
// evaluation alone took.
func timedEvalVars(t *testing.T, contents map[string]string, opts terraform.VarOptions) (*terraform.ParsedModule, map[string]terraform.Variable, time.Duration) {
	t.Helper()
	r, err := fsutil.OpenRoot(files(t, contents))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	var tf []string
	for name := range contents {
		if strings.HasSuffix(name, ".tf") {
			tf = append(tf, name)
		}
	}
	limits := terraform.DefaultLimits()
	m, err := terraform.ParseModule(context.Background(), r, terraform.Dir{Path: ".", Files: sorted(tf)}, limits)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	vars, err := m.EvaluateVariables(context.Background(), r, opts, limits)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	return m, vars, elapsed
}

// A list (not a tuple) passed to a type with optional attributes is unified by typeexpr while
// it applies the defaults: 30,000 objects took 11.4 s (T-0114d review).
func TestOptionalDefaultsOverLargeListsAreBounded(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": "locals {\n  l = tolist([for i in range(1000) : { a = \"x\" }])\n}\n" +
			"module \"net\" {\n  source = \"./net\"\n  t      = concat(" +
			strings.TrimSuffix(strings.Repeat("local.l, ", 30), ", ") + ")\n}\n",
		"net/main.tf": "variable \"t\" {\n  type = list(object({ a = string, b = optional(string, \"d\") }))\n}\n",
	})
	start := time.Now()
	vars, child, _ := childVariables(t, dir, "net")
	if elapsed := time.Since(start); elapsed > 5*time.Second*raceSlowdown {
		t.Errorf("took %v", elapsed)
	}
	if vars["t"].Value.IsKnown() {
		t.Errorf("value is known: %v", diagLines(child))
	}
	if !slices.ContainsFunc(child.Diagnostics, func(d terraform.Diagnostic) bool { return d.Code == terraform.DiagValueTooLarge }) {
		t.Errorf("no value_too_large: %v", diagLines(child))
	}
}

// A sensitive input refused for its size stays sensitive.
func TestRefusedConversionStaysSensitive(t *testing.T) {
	t.Parallel()
	_, vars, err := evalVars(t, ".", map[string]string{
		"main.tf": "variable \"t\" {\n  type      = list(string)\n  sensitive = true\n  default   = " + tupleSource(40_000) + "\n}\n",
	}, terraform.VarOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if v := vars["t"].Value; v.IsKnown() || !v.HasMark(terraform.SensitiveMark) {
		t.Errorf("value %#v, want unknown and sensitive", v.Type().FriendlyName())
	}
}
