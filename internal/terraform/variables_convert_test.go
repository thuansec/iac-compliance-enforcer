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

// distinctObjectsSource is an HCL tuple of n one-element tuples, each holding an object with
// ten attributes no other object has: converted into list(list(any)), each element keeps its own
// type and cty unifies them all (T-0114g review: 11 s at 4,000).
func distinctObjectsSource(n int) string {
	var b strings.Builder
	b.WriteString("[")
	for i := range n {
		b.WriteString("[{")
		for j := range 10 {
			fmt.Fprintf(&b, " a%d_%d = \"x\",", i, j)
		}
		b.WriteString("}], ")
	}
	b.WriteString("]")
	return b.String()
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
		// cty converts these two without unifying, in linear time, so they are not refused
		// (T-0114g).
		"large map default, linear": {known: true, files: map[string]string{
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
		"objects nested into list(list(any))": {files: map[string]string{
			"main.tf": "variable \"t\" {\n  type    = list(list(any))\n  default = " + distinctObjectsSource(4_000) + "\n}\n",
		}},
		"large tfvars, linear": {known: true, files: map[string]string{
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
			// A refused value is refused well under a second; converting took 4.7 to 25 s more.
			// Values that are converted do that linear work, timed by nothing here.
			if !tc.known && elapsed > 3*time.Second*raceSlowdown {
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

// A tfvars value converted into a set(number) variable builds the set, and colliding numbers
// (cty hashes ten significant digits) compare every pair: the conversion is charged, so the
// variable is unknown with value_too_large instead (T-0116).
func TestSetVariablesOfCollidingNumbersAreBounded(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("t = [")
	for i := range 1_500 {
		fmt.Fprintf(&b, "1.%015d, ", i)
	}
	b.WriteString("]\n")
	m, vars, elapsed := timedEvalVars(t, map[string]string{
		"main.tf":    "variable \"t\" {\n  type = set(number)\n}\n",
		"big.tfvars": b.String(),
	}, terraform.VarOptions{VarFiles: []string{"big.tfvars"}})
	if elapsed > time.Second*raceSlowdown {
		t.Errorf("evaluating the variables took %v", elapsed)
	}
	if vars["t"].Value.IsKnown() || !slices.ContainsFunc(m.Diagnostics, func(d terraform.Diagnostic) bool {
		return d.Code == terraform.DiagValueTooLarge
	}) {
		t.Errorf("known %v, diagnostics %v; want unknown with value_too_large", vars["t"].Value.IsKnown(), codes(m))
	}
}

// Quoted numeric strings in tfvars convert to the colliding numbers they spell (T-0116 review:
// 600 of them took 7.3 s into a set(number) variable).
func TestSetVariablesOfNumericStringsAreBounded(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("t = [")
	for i := range 1_500 {
		fmt.Fprintf(&b, "\"1.%015d\", ", i)
	}
	b.WriteString("]\n")
	m, vars, elapsed := timedEvalVars(t, map[string]string{
		"main.tf":    "variable \"t\" {\n  type = set(number)\n}\n",
		"big.tfvars": b.String(),
	}, terraform.VarOptions{VarFiles: []string{"big.tfvars"}})
	if elapsed > time.Second*raceSlowdown {
		t.Errorf("evaluating the variables took %v", elapsed)
	}
	if vars["t"].Value.IsKnown() {
		t.Errorf("known; want unknown with value_too_large: %v", codes(m))
	}
}

// A set(number) variable of distinct numbers is converted, not refused.
func TestSetVariablesOfDistinctNumbersAreKnown(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("t = [")
	for i := range 2_000 {
		fmt.Fprintf(&b, "%d, ", 1024+i)
	}
	b.WriteString("]\n")
	m, vars, _ := timedEvalVars(t, map[string]string{
		"main.tf":    "variable \"t\" {\n  type = set(number)\n}\n",
		"big.tfvars": b.String(),
	}, terraform.VarOptions{VarFiles: []string{"big.tfvars"}})
	if !vars["t"].Value.IsKnown() {
		t.Errorf("unknown: %v", codes(m))
	}
}

// Distinct objects hash apart too: a set(object) variable of a few hundred rules, each with a
// nested list, is converted, and a neighbouring variable keeps its value (T-0116 review: 250
// rules were refused, and 350 blanked the neighbour).
func TestSetVariablesOfDistinctObjectsAreKnown(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("rules = [\n")
	for i := range 400 {
		fmt.Fprintf(&b, "  { description = \"rule %d\", from_port = %d, to_port = %d, protocol = \"tcp\", cidr_blocks = [\"10.0.%d.0/24\", \"10.1.%d.0/24\", \"10.2.%d.0/24\"] },\n",
			i, 1000+i, 1000+i, i%256, i%256, i%256)
	}
	b.WriteString("]\nenv = [\"prod\"]\n")
	m, vars, _ := timedEvalVars(t, map[string]string{
		"main.tf": "variable \"rules\" {\n  type = set(object({ description = string, from_port = number, to_port = number, protocol = string, cidr_blocks = list(string) }))\n}\n" +
			"variable \"env\" {\n  type = set(string)\n}\n",
		"rules.tfvars": b.String(),
	}, terraform.VarOptions{VarFiles: []string{"rules.tfvars"}})
	for _, name := range []string{"rules", "env"} {
		if !vars[name].Value.IsKnown() {
			t.Errorf("%s: unknown: %v", name, codes(m))
		}
	}
}

// A set(any) variable is converted to its elements' unified type first: distinct strings hash
// apart and stay known, with a known neighbour, while colliding numbers are refused (T-0116
// review: set(any) was charged as if every element collided).
func TestSetAnyVariables(t *testing.T) {
	t.Parallel()
	var users, nums strings.Builder
	users.WriteString("users = [")
	nums.WriteString("nums = [")
	for i := range 1_500 {
		fmt.Fprintf(&users, "\"user-%05d@example.com\", ", i)
		fmt.Fprintf(&nums, "1.%015d, ", i)
	}
	users.WriteString("]\n")
	nums.WriteString("]\n")
	m, vars, elapsed := timedEvalVars(t, map[string]string{
		"main.tf":  "variable \"users\" {\n  type = set(any)\n}\nvariable \"nums\" {\n  type = set(any)\n}\nvariable \"env\" {\n  type = set(string)\n}\n",
		"v.tfvars": users.String() + nums.String() + "env = [\"prod\"]\n",
	}, terraform.VarOptions{VarFiles: []string{"v.tfvars"}})
	if elapsed > time.Second*raceSlowdown {
		t.Errorf("evaluating the variables took %v", elapsed)
	}
	for name, known := range map[string]bool{"users": true, "env": true, "nums": false} {
		if got := vars[name].Value.IsKnown(); got != known {
			t.Errorf("%s: known %v, want %v: %v", name, got, known, codes(m))
		}
	}
}

// Estimating a conversion into a set of lists converts the elements as cty does, which is real
// work: a refused variable spends what the estimate did, so a module of many such variables
// stays within its time budget (T-0116 review: twelve of them took 8.6 s, growing with each).
func TestRefusedSetVariablesSpendTheirEstimate(t *testing.T) { // not parallel: it measures time
	var tf, tfvars strings.Builder
	for v := range 12 {
		fmt.Fprintf(&tf, "variable \"v%02d\" {\n  type = set(list(number))\n}\n", v)
		fmt.Fprintf(&tfvars, "v%02d = [[", v)
		for i := range 10_000 {
			fmt.Fprintf(&tfvars, "%d,", i)
		}
		tfvars.WriteString("]")
		for i := range 700 {
			fmt.Fprintf(&tfvars, ", [1.%015d]", i)
		}
		tfvars.WriteString("]\n")
	}
	m, vars, elapsed := timedEvalVars(t, map[string]string{
		"main.tf":    tf.String(),
		"big.tfvars": tfvars.String(),
	}, terraform.VarOptions{VarFiles: []string{"big.tfvars"}})
	if elapsed > 2*time.Second*raceSlowdown {
		t.Errorf("evaluating the variables took %v", elapsed)
	}
	for name, v := range vars {
		if v.Value.IsKnown() {
			t.Errorf("%s: known; want unknown: %v", name, codes(m))
		}
	}
}

// A set(any) value whose element types do not unify is refused, but finding that out unifies
// them, which is real work: each refusal spends it, so a module instantiated many times reaches
// the tree's budget instead of repeating the unification for free (T-0116 review: 50 instances
// with four such defaults took 22 s). With 25 instances of two, it takes about 6 s without both
// guards, the work marked done after unifying and the early return before it when the repeated
// unification does not fit (T-0116c review), against the 3 s limit.
func TestRefusedSetAnyDefaultsSpendTheirUnification(t *testing.T) { // not parallel: it measures time
	var child strings.Builder
	for v := range 2 {
		fmt.Fprintf(&child, "variable \"x%d\" {\n  type    = set(any)\n  default = [{ x = 1 }", v)
		for i := range 4_000 {
			fmt.Fprintf(&child, ", \"%d\"", i)
		}
		child.WriteString("]\n}\n")
	}
	dir := files(t, map[string]string{
		"main.tf":   "module \"c\" {\n  source = \"./c\"\n  count  = 25\n}\n",
		"c/main.tf": child.String(),
	})
	start := time.Now()
	instances := mustEvaluateTree(t, dir)
	if elapsed := time.Since(start); elapsed > 3*time.Second*raceSlowdown {
		t.Errorf("evaluating %d instances took %v", len(instances), elapsed)
	}
}
