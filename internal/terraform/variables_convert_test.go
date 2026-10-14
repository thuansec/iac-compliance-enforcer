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

// setsSource is an HCL tuple of k tuples of n distinct strings.
func setsSource(k, n int) string {
	inner := make([]string, k)
	for i := range inner {
		s := make([]string, n)
		for j := range s {
			s[j] = fmt.Sprintf(`"u-%d-%d"`, i, j)
		}
		inner[i] = "[" + strings.Join(s, ", ") + "]"
	}
	return "[" + strings.Join(inner, ", ") + "]"
}

// cty sorts a set of sets before any walk can count the inner sets, hashing, and so sorting,
// both elements' sets on every comparison: one walk of 100 sets of 200 strings took 2.7 s
// (T-0116d). Such a value is bounded where it is made: every way a scan makes a set whose
// elements hold sets (a variable's default, tfvars or --var value, toset, setunion, a
// conditional) charges building it as if every element collided (setBuildCost: its weight
// squared), so a set of sets holds at most a few thousand units and walks quickly. Larger ones
// are refused before they exist (T-0116i), as are optional() defaults that make one (T-0116k,
// T-0116l). The bound sits below one 2.7 s walk, well above the fixture's own parsing and
// converting (about 0.6 s under load).
func TestSetsOfSetsAreBoundedWhereTheyAreMade(t *testing.T) {
	t.Parallel()
	src := setsSource(100, 200)
	objs := make([]string, 300)
	for i := range objs {
		objs[i] = fmt.Sprintf("{ k = \"%d\" }", i)
	}
	objects300 := strings.Join(objs, ", ")
	list := "variable \"t\" {\n  type    = list(list(string))\n  default = " + src + "\n}\n"
	for name, tc := range map[string]struct {
		files map[string]string
		opts  terraform.VarOptions
		local bool // the set is made by a local, not a variable
	}{
		"default": {files: map[string]string{"main.tf": "variable \"t\" {\n  type    = set(set(string))\n  default = " + src + "\n}\n"}},
		"tfvars": {
			files: map[string]string{"main.tf": "variable \"t\" {\n  type = set(set(string))\n}\n", "a.tfvars": "t = " + src + "\n"},
			opts:  terraform.VarOptions{VarFiles: []string{"a.tfvars"}},
		},
		"--var": {
			files: map[string]string{"main.tf": "variable \"t\" {\n  type = set(set(string))\n}\n"},
			opts:  terraform.VarOptions{Vars: []string{"t=" + src}},
		},
		"defaults inside a set": {files: map[string]string{"main.tf": "variable \"t\" {\n  type    = set(object({ k = string, s = optional(set(string), " + setsSource(1, 200)[1:len(setsSource(1, 200))-1] + ") }))\n  default = [" + objects300 + "]\n}\n"}},
		"toset":                 {files: map[string]string{"main.tf": list + "locals {\n  s = toset([for l in var.t : toset(l)])\n}\n"}, local: true},
		"setunion":              {files: map[string]string{"main.tf": list + "locals {\n  s = setunion([for l in var.t : toset(l)])\n}\n"}, local: true},
		"conditional":           {files: map[string]string{"main.tf": list + "locals {\n  s = true ? [for l in var.t : toset(l)] : toset([toset([\"x\"])])\n}\n"}, local: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, vars, err := evalVars(t, ".", tc.files, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			v := vars["t"].Value
			if tc.local {
				locals, err := m.EvaluateLocals(t.Context(), vars)
				if err != nil {
					t.Fatal(err)
				}
				v = locals["s"].Value
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second*raceSlowdown {
				t.Errorf("took %v", elapsed)
			}
			if v.IsKnown() {
				t.Errorf("the set of sets was made: %v", codes(m))
			}
		})
	}
}

// typeexpr evaluates each optional() default and converts it to its attribute's type itself,
// outside iace's charges: a set(set(string)) default of 100 sets of 200 strings took 6.3 s to
// declare, and one use of it 18 s more (T-0116i review). Each default's evaluation and
// conversion are charged before typeexpr runs; a type whose defaults do not fit is unknown,
// with a warning, as a type too complex to read is, and the variable's value is taken as
// given (T-0116k). Only static literal defaults are read.
func TestOptionalDefaultsAreChargedBeforeTypeexpr(t *testing.T) {
	t.Parallel()
	src := setsSource(100, 200)
	for name, tc := range map[string]struct {
		files map[string]string
		known bool
	}{
		"set of sets":   {files: map[string]string{"main.tf": "variable \"t\" {\n  type    = object({ s = optional(set(set(string)), " + src + ") })\n  default = {}\n}\n"}},
		"nested":        {files: map[string]string{"main.tf": "variable \"t\" {\n  type    = list(object({ o = optional(object({ s = optional(set(set(string)), " + src + ") }), {}) }))\n  default = [{}]\n}\n"}},
		"tuple element": {files: map[string]string{"main.tf": "variable \"t\" {\n  type    = tuple([object({ s = optional(set(set(string)), " + src + ") })])\n  default = [{}]\n}\n"}},
		"map element":   {files: map[string]string{"main.tf": "variable \"t\" {\n  type    = map(object({ s = optional(set(set(string)), " + src + ") }))\n  default = { a = {} }\n}\n"}},
		// typeexpr rejects three arguments, but still reads the inner type and its defaults.
		"three arguments": {files: map[string]string{"main.tf": "variable \"t\" {\n  type    = object({ o = optional(object({ s = optional(set(set(string)), " + src + ") }), {}, 1) })\n  default = {}\n}\n"}},
		"json": {files: map[string]string{"main.tf.json": `{"variable": {"t": {"type": "object({ s = optional(set(set(string)), ` +
			strings.ReplaceAll(src, `"`, `\"`) + `) })", "default": {}}}}`}},
		"small json default": {files: map[string]string{"main.tf.json": `{"variable": {"t": {"type": "object({ s = optional(set(set(string)), ` +
			strings.ReplaceAll(setsSource(2, 3), `"`, `\"`) + `) })", "default": {}}}}`}, known: true},
		// A default that is not a static literal is refused with a warning: iace cannot charge
		// typeexpr's evaluation of it, and a native one's conditional, rewritten by iace, made
		// typeexpr drop the defaults silently.
		"conditional default":      {files: map[string]string{"main.tf": "variable \"t\" {\n  type    = object({ s = optional(set(set(string)), true ? [[\"a\"]] : [[\"b\"]]) })\n  default = {}\n}\n"}},
		"object default":           {files: map[string]string{"main.tf": "variable \"t\" {\n  type    = object({ s = optional(object({ k = string, q = string }), { k = \"v\", \"q\" = \"w\" }), n = optional(number, -1), b = optional(bool, (!true)) })\n  default = {}\n}\n"}, known: true},
		"json conditional default": {files: map[string]string{"main.tf.json": `{"variable": {"t": {"type": "object({ s = optional(set(set(string)), true ? [[\"a\"]] : [[\"b\"]]) })", "default": {}}}}`}},
		"small default":            {files: map[string]string{"main.tf": "variable \"t\" {\n  type    = object({ s = optional(set(set(string)), " + setsSource(2, 3) + ") })\n  default = {}\n}\n"}, known: true},
		// Numeric literal keys stay readable: they are priced from the source, not wrapped
		// (T-0124b review).
		"numeric keys default": {files: map[string]string{"main.tf": "variable \"t\" {\n  type    = object({ s = optional(map(string), { 80 = \"http\", 443 = \"https\" }) })\n  default = {}\n}\n"}, known: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, vars, err := evalVars(t, ".", tc.files, terraform.VarOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second*raceSlowdown {
				t.Errorf("took %v", elapsed)
			}
			refused := slices.ContainsFunc(m.Diagnostics, func(d terraform.Diagnostic) bool {
				return d.Code == terraform.DiagExpressionTooComplex && d.Summary == "Optional defaults not read"
			})
			if refused == tc.known {
				t.Errorf("refused %v, want %v: %v", refused, !tc.known, m.Diagnostics)
			}
			// A refused type is unknown, so the default value is taken as it is, its optional
			// defaults not applied.
			v := vars["t"].Value
			if v.Type().IsListType() || v.Type().IsTupleType() {
				v = v.AsValueSlice()[0]
			}
			if v.Type().IsMapType() || v.Type().IsObjectType() && v.Type().HasAttribute("a") {
				v = v.GetAttr("a")
			}
			if applied := v.Type().IsObjectType() && v.Type().HasAttribute("s") || v.Type().HasAttribute("o"); applied != tc.known {
				t.Errorf("defaults applied %v, want %v: %#v", applied, tc.known, v)
			}
		})
	}
}

// typeexpr applies optional() defaults to every object in a value before it is converted, so a
// value of a few small objects can become a large set of sets that the conversion, charged on
// the value before defaults, never counted: 100 elements of
// set(object({ k = string, s = optional(set(string), [200 strings]) })) were declared with no
// diagnostic, and one length() of them took 4.4 s (T-0116i review; 4.1 s for the locals of 300
// here). The growth the defaults can add is charged first, so the variable is refused where it
// is made (T-0116l).
func TestDefaultsInsideSetsAreCharged(t *testing.T) {
	t.Parallel()
	strs := make([]string, 200)
	for i := range strs {
		strs[i] = fmt.Sprintf("%q", fmt.Sprint("u-", i))
	}
	def := "[" + strings.Join(strs, ", ") + "]"
	elems := func(n int) string {
		e := make([]string, n)
		for i := range e {
			e[i] = fmt.Sprintf("{ k = %q }", fmt.Sprint(i))
		}
		return "[" + strings.Join(e, ", ") + "]"
	}
	// levels nests n lists of objects with 30-object defaults around a set(string) default.
	levels := func(n int, inner string) string {
		ty := "object({ x = optional(set(string), " + inner + ") })"
		for range n {
			ty = "object({ l = optional(list(" + ty + "), [" + strings.Repeat("{}, ", 30) + "]) })"
		}
		return "list(" + ty + ")"
	}
	// chain nests n optional objects, each with a small default beside it.
	chain := func(n int) string {
		ty := "object({ b = optional(string, \"y\") })"
		for range n {
			ty = "object({ a = optional(" + ty + ", {}), b = optional(string, \"y\") })"
		}
		return ty
	}
	rules := func(n int) string {
		e := make([]string, n)
		for i := range e {
			e[i] = fmt.Sprintf("{ cidr = \"10.0.%d.0/24\", ports = [80, 443] }", i)
		}
		return "[" + strings.Join(e, ", ") + "]"
	}
	for name, tc := range map[string]struct {
		src   string
		known bool
	}{
		"set of objects with a set default": {"variable \"t\" {\n  type    = set(object({ k = string, s = optional(set(string), " + def + ") }))\n  default = " + elems(300) + "\n}\nlocals {\n  n = length(var.t)\n}\n", false},
		"few elements, small default":       {"variable \"t\" {\n  type    = set(object({ k = string, s = optional(set(string), [\"a\", \"b\"]) }))\n  default = " + elems(10) + "\n}\nlocals {\n  n = length(var.t)\n}\n", true},
		// Child defaults apply inside inserted defaults, multiplying them (T-0116l review: 40
		// elements each gaining 50 objects that each gain a 200-string set were known after 3 s,
		// and two length() locals took 43.8 s); four levels of 30 objects take 5.1 s and 414 MB in
		// Apply itself on main.
		"defaults within defaults": {"variable \"t\" {\n  type    = set(object({ k = string, s = optional(list(object({ x = optional(set(string), " + def + ") })), [" + strings.Repeat("{}, ", 50) + "]) }))\n  default = " + elems(40) + "\n}\nlocals {\n  n = length(var.t)\n}\n", false},
		"four levels":              {"variable \"t\" {\n  type    = " + levels(4, def) + "\n  default = [{}]\n}\nlocals {\n  n = length(var.t)\n}\n", false},
		// A chain of 40 nested optional objects is computed once per level, not twice: the
		// estimate doubled per level, so a short type could hang the scan (T-0116l review).
		"deep chain": {"variable \"t\" {\n  type    = list(" + chain(40) + ")\n  default = [{}]\n}\nlocals {\n  n = length(var.t)\n}\n", true},
		// Security group rules with small optional defaults stay cheap: the default's growth is
		// charged as a walk prices it, not squared.
		"rules with small defaults": {"variable \"t\" {\n  type    = set(object({ cidr = string, ports = optional(set(number), []), desc = optional(string, \"managed\") }))\n  default = " + rules(200) + "\n}\nlocals {\n  n = length(var.t)\n}\n", true},
		"list of objects, linear":   {"variable \"t\" {\n  type    = list(object({ k = string, s = optional(list(string), " + def + ") }))\n  default = " + elems(100) + "\n}\nlocals {\n  n = length(var.t)\n}\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			m, vars, err := evalVars(t, ".", map[string]string{"main.tf": tc.src}, terraform.VarOptions{})
			if err != nil {
				t.Fatal(err)
			}
			// The variable is refused where it is made, not at its first use (4.1 s at 300).
			if v := vars["t"].Value; v.IsKnown() != tc.known {
				t.Errorf("variable known %v, want %v: %v", v.IsKnown(), tc.known, codes(m))
			}
			locals, err := m.EvaluateLocals(t.Context(), vars)
			if err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second*raceSlowdown {
				t.Errorf("took %v", elapsed)
			}
			if n := locals["n"].Value; n.IsKnown() != tc.known {
				t.Errorf("length known %v, want %v: %v", n.IsKnown(), tc.known, codes(m))
			}
		})
	}
}

// Module inputs are converted to the child's variable type like any value, defaults included:
// a parent passing 300 objects that the child's defaults would each give a 200-string set is
// refused in the child with value_too_large (T-0116l review).
func TestModuleInputDefaultsInsideSetsAreCharged(t *testing.T) {
	t.Parallel()
	strs := make([]string, 200)
	for i := range strs {
		strs[i] = fmt.Sprintf("%q", fmt.Sprint("u-", i))
	}
	objs := make([]string, 300)
	for i := range objs {
		objs[i] = fmt.Sprintf("{ k = \"%d\" }", i)
	}
	dir := files(t, map[string]string{
		"main.tf":     "module \"net\" {\n  source = \"./net\"\n  t      = [" + strings.Join(objs, ", ") + "]\n}\n",
		"net/main.tf": "variable \"t\" {\n  type = set(object({ k = string, s = optional(set(string), [" + strings.Join(strs, ", ") + "]) }))\n}\n",
	})
	start := time.Now()
	vars, child, _ := childVariables(t, dir, "net")
	if elapsed := time.Since(start); elapsed > 2*time.Second*raceSlowdown {
		t.Errorf("took %v", elapsed)
	}
	if vars["t"].Value.IsKnown() {
		t.Errorf("known: %v", diagLines(child))
	}
	if !slices.ContainsFunc(child.Diagnostics, func(d terraform.Diagnostic) bool { return d.Code == terraform.DiagValueTooLarge }) {
		t.Errorf("no value_too_large: %v", diagLines(child))
	}
}
