package terraform

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// evalLocal evaluates `v = expr` in a module's locals with vars.
func evalLocal(t *testing.T, expr string, vars map[string]Variable) (*ParsedModule, cty.Value) {
	t.Helper()
	m := parseLocalsModule(t, "locals {\n  v = "+expr+"\n}\n")
	locals, err := m.EvaluateLocals(context.Background(), vars)
	if err != nil {
		t.Fatal(err)
	}
	return m, locals["v"].Value
}

// parseFilesModule parses one module directory holding files.
func parseFilesModule(t *testing.T, files map[string]string) *ParsedModule {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	m, err := ParseModule(context.Background(), r, Dir{Path: ".", Files: slices.Sorted(maps.Keys(files))}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// literal evaluates an HCL literal expression without functions or variables.
func literal(t *testing.T, src string) cty.Value {
	t.Helper()
	expr, diags := hclsyntax.ParseExpression([]byte(src), "want", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatalf("parse %q: %v", src, diags)
	}
	v, diags := expr.Value(nil)
	if diags.HasErrors() {
		t.Fatalf("evaluate %q: %v", src, diags)
	}
	return v
}

// TestSupportedFunctions has a case for every function in the table, each evaluated in a local
// the way Terraform evaluates it.
func TestSupportedFunctions(t *testing.T) {
	t.Parallel()
	cases := map[string]struct{ expr, want string }{
		"chomp":      {`chomp("a\n")`, `"a"`},
		"format":     {`format("%s-%03d", "a", 7)`, `"a-007"`},
		"formatlist": {`formatlist("%s!", ["a", "b"])`, `["a!", "b!"]`},
		"join":       {`join("-", ["a", "b"], ["c"])`, `"a-b-c"`},
		"lower":      {`lower("AbC")`, `"abc"`},
		"split":      {`split(",", "a,b")`, `["a", "b"]`},
		"substr":     {`substr("hello", 1, 3)`, `"ell"`},
		"title":      {`title("hello world")`, `"Hello World"`},
		"trim":       {`trim("?!a!?", "!?")`, `"a"`},
		"trimprefix": {`trimprefix("arn:aws", "arn:")`, `"aws"`},
		"trimspace":  {`trimspace(" a\n")`, `"a"`},
		"trimsuffix": {`trimsuffix("a.tf", ".tf")`, `"a"`},
		"upper":      {`upper("abc")`, `"ABC"`},

		"cidrhost":        {`cidrhost("10.0.0.0/24", 5)`, `"10.0.0.5"`},
		"cidrnetmask":     {`cidrnetmask("10.0.0.0/8")`, `"255.0.0.0"`},
		"cidrsubnet":      {`cidrsubnet("10.0.0.0/16", 8, 1)`, `"10.0.1.0/24"`},
		"chunklist":       {`chunklist([1, 2, 3], 2)`, `[[1, 2], [3]]`},
		"coalescelist":    {`coalescelist([], ["a"])`, `["a"]`},
		"compact":         {`compact(["a", "", "b"])`, `["a", "b"]`},
		"concat":          {`concat(["a"], ["b"])`, `["a", "b"]`},
		"contains":        {`contains(["a", "b"], "b")`, `true`},
		"distinct":        {`distinct(["b", "a", "b", 1])`, `["b", "a", "1"]`},
		"element":         {`element(["a", "b"], 3)`, `"b"`},
		"flatten":         {`flatten([["a"], ["b", ["c"]]])`, `["a", "b", "c"]`},
		"keys":            {`keys({ b = 1, a = 2 })`, `["a", "b"]`},
		"merge":           {`merge({ a = 1 }, { b = 2, a = 3 })`, `{ a = 3, b = 2 }`},
		"range":           {`range(1, 7, 2)`, `[1, 3, 5]`},
		"reverse":         {`reverse(["a", "b"])`, `["b", "a"]`},
		"setintersection": {`setintersection(["a", "b"], ["b", "c"], ["b"])`, `["b"]`},
		"setsubtract":     {`setsubtract(["a", "b"], ["b", "c"])`, `["a"]`},
		"setunion":        {`setunion(["a"], ["b", "a"], [])`, `["a", "b"]`},
		"slice":           {`slice(["a", "b", "c"], 1, 2)`, `["b"]`},
		"sort":            {`sort(["b", "a"])`, `["a", "b"]`},
		"values":          {`values({ b = 1, a = 2 })`, `[2, 1]`},
		"zipmap":          {`zipmap(["a", "b"], [1, 2])`, `{ a = 1, b = 2 }`},

		"can":      {`can(tonumber("x"))`, `false`},
		"tobool":   {`tobool("true")`, `true`},
		"tolist":   {`tolist(["a", "b"])`, `["a", "b"]`},
		"tomap":    {`tomap({ a = "x" })`, `{ a = "x" }`},
		"tonumber": {`tonumber("5")`, `5`},
		"toset":    {`toset(["b", "a", "b"])`, `["a", "b"]`},
		"tostring": {`tostring(5)`, `"5"`},
		"try":      {`try(tonumber("x"), 7)`, `7`},

		"jsondecode": {`jsondecode("{\"a\":[1,true]}")`, `{ a = [1, true] }`},
		"jsonencode": {`jsonencode({ b = [1, "x"], a = null })`, `"{\"a\":null,\"b\":[1,\"x\"]}"`},

		"base64decode": {`base64decode("aMOpbGxv")`, `"héllo"`},
		"base64encode": {`base64encode("héllo")`, `"aMOpbGxv"`},
		"coalesce":     {`coalesce(null, "", "b", "c")`, `"b"`},
		"endswith":     {`endswith("main.tf", ".tf")`, `true`},
		"index":        {`index(["a", "b", "c"], "b")`, `1`},
		"length":       {`length("éx")`, `2`},
		"lookup":       {`lookup({ a = "x" }, "b", "d")`, `"d"`},
		"startswith":   {`startswith("arn:aws:s3", "arn:")`, `true`},
		"strcontains":  {`strcontains("hello", "ell")`, `true`},

		"abs":    {`abs(-2)`, `2`},
		"max":    {`max(1, 3, 2)`, `3`},
		"min":    {`min(1, 3, 2)`, `1`},
		"signum": {`signum(-5)`, `-1`},
	}
	if diff := cmp.Diff(slices.Sorted(maps.Keys(cases)), tableNames()); diff != "" {
		t.Errorf("a case for every function (-cases +table):\n%s", diff)
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, got := evalLocal(t, c.expr, nil)
			if len(m.Diagnostics) != 0 {
				t.Fatalf("%s: diagnostics %v", c.expr, m.Diagnostics)
			}
			want, err := convert.Convert(literal(t, c.want), got.Type())
			if err != nil || !got.Type().Equals(want.Type()) || !got.Equals(want).True() {
				t.Errorf("%s = %#v, want %s", c.expr, got, c.want)
			}
		})
	}
}

func tableNames() []string {
	return slices.Sorted(func(yield func(string) bool) {
		for name := range supportedFunctions {
			if !yield(name) {
				return
			}
		}
		for name := range unboundedFunctions {
			if !yield(name) {
				return
			}
		}
	})
}

// TestFunctionTableMatchesReference: the supported-functions table in the reference lists
// exactly the functions in the code.
func TestFunctionTableMatchesReference(t *testing.T) {
	t.Parallel()
	doc, err := os.ReadFile("../../docs/reference/terraform-functions.md")
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(doc), "## Supported functions")
	section, _, _ := strings.Cut(after, "\n## ")
	if !ok {
		t.Fatal("the reference has no Supported functions section")
	}
	var names []string
	for line := range strings.SplitSeq(section, "\n") {
		if strings.HasPrefix(line, "| ") && strings.Contains(line, "`") {
			for _, m := range regexp.MustCompile("`([a-z0-9_]+)`").FindAllStringSubmatch(line, -1) {
				names = append(names, m[1])
			}
		}
	}
	slices.Sort(names)
	if diff := cmp.Diff(slices.Sorted(slices.Values(append(tableNames(), moduleFunctionNames...))), names); diff != "" {
		t.Errorf("reference table (-code +doc):\n%s", diff)
	}
}

func TestCoreNamespace(t *testing.T) {
	t.Parallel()
	m, got := evalLocal(t, `core::upper("a")`, nil)
	if !got.RawEquals(cty.StringVal("A")) || len(m.Diagnostics) != 0 {
		t.Errorf("core::upper(\"a\") = %#v, diagnostics %v", got, m.Diagnostics)
	}
}

// TestUnsupportedFunctionsAreUnknown: impure, provider-defined, unbounded and undefined
// functions are unknown, never errors, with one warning per name per module at its first call.
func TestUnsupportedFunctionsAreUnknown(t *testing.T) {
	t.Parallel()
	m := parseLocalsModule(t, `locals {
  a = timestamp()
  b = "${timestamp()}-${provider::aws::arn_parse("arn:aws:s3:::x").service}"
  c = { k = upper(nosuchfunction(1, [2], null)) }
  d = core::uuid()
  e = upper("kept")
}
`)
	locals, err := m.EvaluateLocals(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "d"} {
		if locals[name].Value.IsKnown() {
			t.Errorf("local.%s = %#v, want unknown", name, locals[name].Value)
		}
	}
	if c := locals["c"].Value; !c.IsKnown() || c.GetAttr("k").IsKnown() {
		t.Errorf("local.c = %#v, want an object with an unknown k", c)
	}
	if e := locals["e"].Value; !e.RawEquals(cty.StringVal("KEPT")) {
		t.Errorf("local.e = %#v, want \"KEPT\"", e)
	}
	var got []string
	for _, d := range m.Diagnostics {
		got = append(got, string(d.Code)+"@"+strconv.Itoa(d.Line)+":"+strconv.Itoa(d.Column)+" "+d.Summary)
	}
	want := []string{
		`unsupported_function@2:7 Unsupported function "timestamp"`,
		`unsupported_function@3:25 Unsupported function "provider::aws::arn_parse"`,
		`unsupported_function@4:19 Unsupported function "nosuchfunction"`,
		`unsupported_function@5:7 Unsupported function "core::uuid"`,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
	// A second evaluation reports nothing new.
	if _, err := m.EvaluateLocals(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(m.Diagnostics) != len(want) {
		t.Errorf("after a second evaluation: %v", m.Diagnostics)
	}
}

func TestUnsupportedFunctionInJSON(t *testing.T) {
	t.Parallel()
	m := parseFilesModule(t, map[string]string{
		"main.tf.json": "{\n  \"locals\": {\n    \"v\": \"${uuid()}-${upper(\\\"a\\\")}\"\n  }\n}\n",
	})
	locals, err := m.EvaluateLocals(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if locals["v"].Value.IsKnown() {
		t.Errorf("local.v = %#v, want unknown", locals["v"].Value)
	}
	if diff := cmp.Diff([]DiagCode{DiagUnsupportedFunction}, diagCodes(m)); diff != "" {
		t.Fatalf("diagnostics (-want +got):\n%s", diff)
	}
	if d := m.Diagnostics[0]; d.Line != 3 || d.Column != 10 || d.Summary != `Unsupported function "uuid"` {
		t.Errorf("diagnostic %v, want line 3 column 10 (the expression) naming uuid", d)
	}
}

// TestFunctionsKeepSensitivity: a result computed from a sensitive argument is sensitive,
// whether the function is supported, unsupported or over a limit.
func TestFunctionsKeepSensitivity(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"s":   {Value: cty.StringVal("secret").Mark(SensitiveMark)},
		"big": {Value: cty.StringVal(strings.Repeat("x", maxFunctionValueSize)).Mark(SensitiveMark)},
	}
	for _, expr := range []string{
		`upper(var.s)`,
		`element([var.s], 0)`,
		`bcrypt(var.s)`,
		`provider::aws::x(var.s)`,
		`upper(var.big)`,
		`element([var.big], 0)`,
	} {
		_, got := evalLocal(t, expr, vars)
		if !got.HasMark(SensitiveMark) {
			t.Errorf("%s = %#v, want sensitive", expr, got)
		}
	}
	// Over the limit, element (whose list parameter accepts marks) is unknown and still sensitive.
	big := cty.ListVal([]cty.Value{vars["big"].Value})
	got, limited := boundedCall(t, &ParsedModule{}, "element", big, cty.NumberIntVal(0))
	if !limited || got.IsKnown() || !got.HasMark(SensitiveMark) {
		t.Errorf("element over the limit = %#v (limited %v), want unknown and sensitive", got, limited)
	}
}

func TestSyntaxCalls(t *testing.T) {
	t.Parallel()
	for src, want := range map[string][]string{
		`a(b(1), c)`:                        {"a", "b"},
		`provider::aws::arn_parse(x)`:       {"provider::aws::arn_parse"},
		`core::upper("a")`:                  {"core::upper"},
		`"f(x) ${g(1)}"`:                    {"g"},
		`x + y`:                             nil,
		`[for k, v in m : f(v) if g(k)]`:    {"f", "g"},
		`[for x in (local.l) : x]`:          nil,
		`"%{ if (true) }y%{ endif }"`:       nil,
		"<<EOT\n${h(1)} i(2)\nEOT\n":        {"h"},
		"[\n  uuid(\n  )\n]":                {"uuid"},
		`try(local.a.b, null)`:              {"try"},
		`{ k = jsonencode({ a = upper }) }`: {"jsonencode"},
	} {
		expr, diags := hclsyntax.ParseExpression([]byte(src), "t", hcl.InitialPos)
		if diags.HasErrors() {
			t.Fatalf("parse %q: %v", src, diags)
		}
		var got []string
		for _, c := range syntaxCalls(expr) {
			got = append(got, c.name)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("syntaxCalls(%q) (-want +got):\n%s", src, diff)
		}
	}
}

// boundedCall calls name from a fresh module's function table, and reports whether the call
// was over a limit.
func boundedCall(t *testing.T, m *ParsedModule, name string, args ...cty.Value) (cty.Value, bool) {
	t.Helper()
	m.fnLimited = false
	got, err := m.functions(nil, nil)[name].Call(args)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return got, m.fnLimited
}

func TestFunctionArgumentAndResultLimits(t *testing.T) {
	t.Parallel()
	str := func(n int) cty.Value { return cty.StringVal(strings.Repeat("x", n)) }
	// A string of n bytes has size n+1; upper keeps the size.
	for _, c := range []struct {
		n       int
		limited bool
	}{
		{maxFunctionValueSize - 2, false},
		{maxFunctionValueSize - 1, false},
		{maxFunctionValueSize, true},
	} {
		got, limited := boundedCall(t, &ParsedModule{}, "upper", str(c.n))
		if limited != c.limited || got.IsKnown() == c.limited {
			t.Errorf("upper(%d bytes): limited %v, known %v; want limited %v", c.n, limited, got.IsKnown(), c.limited)
		}
	}
	// Two arguments count together: join("", [s]) has size 1 + (1 + (n+1)) for separator and list.
	for _, c := range []struct {
		n       int
		limited bool
	}{
		{maxFunctionValueSize - 3, false},
		{maxFunctionValueSize - 2, true},
	} {
		_, limited := boundedCall(t, &ParsedModule{}, "join", cty.StringVal(""), cty.ListVal([]cty.Value{str(c.n)}))
		if limited != c.limited {
			t.Errorf("join over %d bytes: limited %v, want %v", c.n, limited, c.limited)
		}
	}
	// The result counts on its own: jsonencode escapes each `"` as two bytes and adds two quotes,
	// so q quotes and p plain bytes encode to a string of size 2q+p+3.
	const q = 1000
	for _, c := range []struct {
		p       int
		limited bool
	}{
		{maxFunctionValueSize - 2*q - 4, false},
		{maxFunctionValueSize - 2*q - 3, false},
		{maxFunctionValueSize - 2*q - 2, true},
	} {
		s := cty.StringVal(strings.Repeat(`"`, q) + strings.Repeat("x", c.p))
		got, limited := boundedCall(t, &ParsedModule{}, "jsonencode", s)
		if limited != c.limited || got.IsKnown() == c.limited {
			t.Errorf("jsonencode(%d+%d bytes): limited %v, known %v; want limited %v", q, c.p, limited, got.IsKnown(), c.limited)
		}
	}
	// A result nested deeper than maxNesting is over the limit: n brackets nest values n-1 deep.
	for _, c := range []struct {
		n       int
		limited bool
	}{
		{maxNesting, false},
		{maxNesting + 1, false},
		{maxNesting + 2, true},
	} {
		s := cty.StringVal(strings.Repeat("[", c.n) + strings.Repeat("]", c.n))
		if _, limited := boundedCall(t, &ParsedModule{}, "jsondecode", s); limited != c.limited {
			t.Errorf("jsondecode(%d brackets): limited %v, want %v", c.n, limited, c.limited)
		}
	}
}

func TestFormatLimits(t *testing.T) {
	t.Parallel()
	// format("%Ns", "") is bounded by len(f) + N + 6*size(""), and "%262130s" is 8 bytes.
	for _, c := range []struct {
		width   int
		limited bool
	}{
		{maxFunctionValueSize - 15, false},
		{maxFunctionValueSize - 14, false},
		{maxFunctionValueSize - 13, true},
	} {
		f := "%" + strconv.Itoa(c.width) + "s"
		if len(f) != 8 {
			t.Fatalf("format string %q is not 8 bytes", f)
		}
		got, limited := boundedCall(t, &ParsedModule{}, "format", cty.StringVal(f), cty.StringVal(""))
		if limited != c.limited || got.IsKnown() == c.limited {
			t.Errorf("format(%q): limited %v, known %v; want limited %v", f, limited, got.IsKnown(), c.limited)
		}
	}
	// formatlist("%s", list) is bounded by rows * (2 + 6*5), each "xxxx" having size 5.
	list := func(n int) cty.Value {
		return cty.ListVal(slices.Repeat([]cty.Value{cty.StringVal("xxxx")}, n))
	}
	for _, c := range []struct {
		rows    int
		limited bool
	}{
		{maxFunctionValueSize/32 - 1, false},
		{maxFunctionValueSize / 32, false},
		{maxFunctionValueSize/32 + 1, true},
	} {
		if _, limited := boundedCall(t, &ParsedModule{}, "formatlist", cty.StringVal("%s"), list(c.rows)); limited != c.limited {
			t.Errorf("formatlist over %d rows: limited %v, want %v", c.rows, limited, c.limited)
		}
	}
}

func TestFormatBound(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		f       string
		largest int
		want    int
	}{
		{"abc", 100, 3},
		{"%s", 10, 2 + 60},
		{"%%", 10, 2},
		{"%5d", 0, 3 + 5},
		{"%.3f", 0, 4 + 3},
		{"%-8.3q", 1, 6 + 8 + 3 + 6},
		{"%[1]s%[1]s", 2, 10 + 2*(1+12)},
		{"%", 1, 1 + 6},
		{"%99999999999999999999d", 0, maxFunctionValueSize + 1},
		{"%s", maxFunctionWork, maxFunctionValueSize + 1},
	} {
		if got := formatBound(c.f, c.largest); got != c.want {
			t.Errorf("formatBound(%q, %d) = %d, want %d", c.f, c.largest, got, c.want)
		}
	}
}

// TestFunctionWorkBudget: the module's calls share maxFunctionWork.
func TestFunctionWorkBudget(t *testing.T) {
	t.Parallel()
	m := &ParsedModule{}
	if !m.chargeFunctionWork(maxFunctionWork-1, 1) || m.fnWork != maxFunctionWork {
		t.Fatalf("charging exactly maxFunctionWork failed: %d", m.fnWork)
	}
	if m.chargeFunctionWork(1) || m.fnWork != maxFunctionWork {
		t.Errorf("charging past maxFunctionWork succeeded: %d", m.fnWork)
	}
	if (&ParsedModule{}).chargeFunctionWork(maxFunctionWork, maxFunctionWork) {
		t.Error("two amounts that pass maxFunctionWork together were charged")
	}

	// upper("ab") costs 3 for its argument and 3 for its result.
	for _, c := range []struct {
		used    int
		limited bool
	}{
		{maxFunctionWork - 7, false},
		{maxFunctionWork - 6, false},
		{maxFunctionWork - 5, true},
	} {
		m := &ParsedModule{fnWork: c.used}
		if _, limited := boundedCall(t, m, "upper", cty.StringVal("ab")); limited != c.limited {
			t.Errorf("upper with %d work used: limited %v, want %v", c.used, limited, c.limited)
		}
	}
}

// TestFunctionLimitIsReported: a local whose call is over a limit is unknown with a
// function_limit warning at its expression, not an error.
func TestFunctionLimitIsReported(t *testing.T) {
	t.Parallel()
	m, got := evalLocal(t, `{ a = format("%999999s", ""), b = "kept" }`, nil)
	if !got.IsKnown() || got.GetAttr("a").IsKnown() || !got.GetAttr("b").RawEquals(cty.StringVal("kept")) {
		t.Errorf("local.v = %#v, want a unknown and b kept", got)
	}
	if diff := cmp.Diff([]DiagCode{DiagFunctionLimit}, diagCodes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
	if m.HasErrors() {
		t.Error("a function limit must not be an error")
	}
}

// TestRangeLimit: go-cty's range stops at 1,024 elements; past that the local is unknown.
func TestRangeLimit(t *testing.T) {
	t.Parallel()
	if _, got := evalLocal(t, `range(1024)`, nil); !got.IsKnown() || got.LengthInt() != 1024 {
		t.Errorf("range(1024) = %#v, want 1,024 elements", got)
	}
	if _, got := evalLocal(t, `range(1025)`, nil); got.IsKnown() {
		t.Errorf("range(1025) = %#v, want unknown", got)
	}
}

// TestBoundedKeepsSignature: wrapping keeps each function's parameters, except that they take
// any type, so cty treats unknown, null and marked arguments the same way.
func TestBoundedKeepsSignature(t *testing.T) {
	t.Parallel()
	m := &ParsedModule{}
	for name, f := range supportedFunctions {
		b := m.bounded(f, nil, nil)
		if !slices.EqualFunc(f.Params(), b.Params(), paramsEqual) || (f.VarParam() == nil) != (b.VarParam() == nil) ||
			(f.VarParam() != nil && !paramsEqual(*f.VarParam(), *b.VarParam())) {
			t.Errorf("%s: bounded parameters differ", name)
		}
	}
	got, _ := boundedCall(t, m, "upper", cty.UnknownVal(cty.String))
	if got.IsKnown() {
		t.Error("upper(unknown) is known")
	}
	if _, err := m.functions(nil, nil)["upper"].Call([]cty.Value{cty.NullVal(cty.String)}); err == nil {
		t.Error("upper(null) did not fail as in go-cty")
	}
}

func paramsEqual(a, b function.Parameter) bool {
	return a.Name == b.Name && b.Type.Equals(cty.DynamicPseudoType) && a.AllowNull == b.AllowNull && a.AllowUnknown == b.AllowUnknown &&
		a.AllowDynamicType == b.AllowDynamicType && a.AllowMarked == b.AllowMarked
}

// TestBoundedConvertsArguments: the wrapper converts arguments as hcl would, and rejects a
// conversion that fails.
func TestBoundedConvertsArguments(t *testing.T) {
	t.Parallel()
	m, got := evalLocal(t, `[join(",", [1, true, "x"]), upper(5)]`, nil)
	want := cty.TupleVal([]cty.Value{cty.StringVal("1,true,x"), cty.StringVal("5")})
	if !got.RawEquals(want) || len(m.Diagnostics) != 0 {
		t.Errorf("got %#v, diagnostics %v; want %#v", got, m.Diagnostics, want)
	}
	m, got = evalLocal(t, `upper(["x"])`, nil)
	if got.IsKnown() || !slices.Equal(diagCodes(m), []DiagCode{DiagEvaluation}) {
		t.Errorf("upper([\"x\"]) = %#v, diagnostics %v; want unknown with an evaluation warning", got, m.Diagnostics)
	}
}

// TestNumberDigitsCount: a number's size grows with its decimal digits, so huge numbers are
// over the limit before cty formats or converts them.
func TestNumberDigitsCount(t *testing.T) {
	t.Parallel()
	// At least the digits cty writes, and at most 155 more (the 512-bit mantissa).
	for _, c := range []struct {
		src  string
		want int
	}{
		{"0", 0},
		{"5", 0},
		{"1024", 3},
		{"0.1", 150},
		{"0.5000123", 150},
		{"1e100", 100},
		{"1e-100", 100},
		{"1e6000000", 6000000},
	} {
		got := numberDigits(literal(t, c.src))
		if got < c.want || got > c.want+155 {
			t.Errorf("numberDigits(%s) = %d, want %d to %d", c.src, got, c.want, c.want+155)
		}
	}
	// Many high-precision fractions: comparing or formatting them costs about 150 digits each.
	var fracs []string
	for i := range 2000 {
		fracs = append(fracs, "0.5"+strconv.Itoa(1000000+i))
	}
	list, err := stdlib.JSONDecodeFunc.Call([]cty.Value{cty.StringVal("[" + strings.Join(fracs, ",") + "]")})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		args []cty.Value
	}{
		{"contains", []cty.Value{list, cty.NumberFloatVal(0.25)}},
		{"jsonencode", []cty.Value{list}},
	} {
		if _, limited := boundedCall(t, &ParsedModule{}, c.name, c.args...); !limited {
			t.Errorf("%s over 2,000 high-precision fractions was not limited", c.name)
		}
	}
	huge := literal(t, "1e2000000")
	for _, name := range []string{"tostring", "jsonencode"} {
		if got, limited := boundedCall(t, &ParsedModule{}, name, huge); !limited || got.IsKnown() {
			t.Errorf("%s(1e2000000) = %#v (limited %v), want unknown and limited", name, got, limited)
		}
	}
	// join converts the number to a string: that must happen only after the size check.
	if _, limited := boundedCall(t, &ParsedModule{}, "join", cty.StringVal(","), cty.TupleVal([]cty.Value{huge})); !limited {
		t.Error("join over 1e2000000 was not limited")
	}
	if _, limited := boundedCall(t, &ParsedModule{}, "tonumber", cty.StringVal("1e2000000")); !limited {
		t.Error("tonumber(\"1e2000000\") was not limited")
	}
}

// collidingNumbers is a tuple of n numbers that differ past ten significant digits, so they
// share a cty hash and a set of them compares every pair.
func collidingNumbers(n int) string {
	return fmt.Sprintf("[for j in range(%d) : 1 + j / 1e15]", n)
}

// TestSetFunctionsAreCharged: building a set of close numbers compares every pair, and distinct
// always does. These calls took 20s before the charge; now they are refused before the work.
func TestSetFunctionsAreCharged(t *testing.T) {
	t.Parallel()
	nums := collidingNumbers(1024)
	for _, expr := range []string{
		"toset(" + nums + ")",
		"distinct(" + nums + ")",
		"setunion(" + nums + ")",
		"setunion([], " + nums + ")",
		"setintersection(" + nums + ", " + nums + ")",
		"setsubtract(" + nums + ", [])",
	} {
		// Without the charge the call runs (seconds, more under -race) and is known, so the
		// limit itself is the assertion; wall-clock checks are flaky.
		m, got := evalLocal(t, expr, nil)
		if got.IsKnown() || !slices.Equal(diagCodes(m), []DiagCode{DiagFunctionLimit}) {
			t.Errorf("%.40s… = %#v, diagnostics %v; want unknown with function_limit", expr, got, m.Diagnostics)
		}
	}
	// A smaller set of colliding numbers is still built, and keeps every number.
	small := collidingNumbers(24)
	m, got := evalLocal(t, "[length(toset("+collidingNumbers(48)+")), length(distinct(concat("+small+", "+small+")))]", nil)
	if len(m.Diagnostics) != 0 || !got.RawEquals(cty.TupleVal([]cty.Value{cty.NumberIntVal(48), cty.NumberIntVal(24)})) {
		t.Errorf("small colliding sets = %#v, diagnostics %v; want [48, 24]", got, m.Diagnostics)
	}
}

// TestNestedSetsAreChargedPairwise: comparing two sets compares their elements pairwise when
// hashes collide, so a set of sets is charged its size squared.
func TestNestedSetsAreChargedPairwise(t *testing.T) {
	t.Parallel()
	nums := collidingNumbers(40) // each inner set is affordable, the outer one only if not squared
	for _, expr := range []string{
		"toset([toset(" + nums + "), toset(concat(" + nums + ", [2]))])",
		"distinct([toset(" + nums + "), toset(concat(" + nums + ", [2]))])",
		"setunion([toset(" + nums + ")], [toset(concat(" + nums + ", [2]))])",
	} {
		m, got := evalLocal(t, expr, nil)
		if got.IsKnown() || !slices.Equal(diagCodes(m), []DiagCode{DiagFunctionLimit}) {
			t.Errorf("%.40s… = %#v, diagnostics %v; want unknown with function_limit", expr, got, m.Diagnostics)
		}
	}
	// Small nested sets are built.
	if _, got := evalLocal(t, `length(toset([toset([1, 2]), toset([2, 1]), toset([3])]))`, nil); !got.RawEquals(cty.NumberIntVal(2)) {
		t.Errorf("small nested sets = %#v, want 2", got)
	}
}

func TestSetBuildCost(t *testing.T) {
	t.Parallel()
	str := cty.StringVal
	set := func(vs ...cty.Value) cty.Value { return cty.SetVal(vs) }
	// Sizes: one per value and string byte, and a set's element counts again as its key.
	cases := []struct {
		name string
		args []cty.Value
		want int
	}{
		{"elements times size", []cty.Value{cty.TupleVal([]cty.Value{str("a"), str("bb")})}, 2 * 6},
		{"over every argument", []cty.Value{cty.ListVal([]cty.Value{str("a")}), set(str("b"), str("c"))}, 3 * (3 + 7)},
		{"marked argument", []cty.Value{cty.ListVal([]cty.Value{str("a")}).Mark(SensitiveMark)}, 1 * 3},
		{"unknown and null", []cty.Value{cty.UnknownVal(cty.List(cty.String)), cty.NullVal(cty.Set(cty.String))}, 0},
		{"nested sets: size squared", []cty.Value{cty.TupleVal([]cty.Value{set(str("a")), set(str("b"))})}, 9 * 9},
		{"dynamic elements", []cty.Value{cty.ListVal([]cty.Value{cty.DynamicVal})}, 2 * 2},
		// 10 counts 2 digits; 0.5 counts none, and 1 for formatting its fractional bit.
		{"numbers weigh their formatting", []cty.Value{cty.TupleVal([]cty.Value{cty.NumberIntVal(10), cty.NumberFloatVal(0.5)})}, 2 * (1 + (1 + 2) + (1 + 0 + 1))},
	}
	for _, c := range cases {
		sizes := make([]int, len(c.args))
		for i, a := range c.args {
			sizes[i], _ = valueSize(a, maxFunctionValueSize, maxNesting)
		}
		if _, got := setBuildCost(c.args, sizes); got != c.want {
			t.Errorf("%s: work %d, want %d", c.name, got, c.want)
		}
	}
}

// TestTinyNumbersAreChargedTheirFormatting: cty compares numbers by their exact decimal text,
// which math/big builds in time quadratic in the fractional bits; one comparison of 1e-78000
// took 1.9s, and its digits alone are a fraction of the budget.
func TestTinyNumbersAreChargedTheirFormatting(t *testing.T) {
	t.Parallel()
	for _, expr := range []string{
		"toset([1e-78000])",
		"distinct([1e-78000, 0.5])",
		"setunion([1e-78000], [0.5])",
		"setsubtract([1e-40000], [0.5])",
	} {
		m, got := evalLocal(t, expr, nil)
		if got.IsKnown() || !slices.Equal(diagCodes(m), []DiagCode{DiagFunctionLimit}) {
			t.Errorf("%s = %#v, diagnostics %v; want unknown with function_limit", expr, got, m.Diagnostics)
		}
	}
	// Moderately small numbers are still compared.
	if _, got := evalLocal(t, "length(distinct([1e-1000, 2e-1000, 1e-1000]))", nil); !got.RawEquals(cty.NumberIntVal(2)) {
		t.Errorf("distinct of small numbers = %#v, want 2", got)
	}
}

func TestNumberFormatCost(t *testing.T) {
	t.Parallel()
	cases := map[string]int{
		"0":        0,
		"1e78000":  0, // integers compare as integers and format in near-linear time
		"-12":      0,
		"0.5":      1,                   // 1 fractional bit
		"0.75":     1,                   // 2
		"1.5e-19":  324,                 // 511 + 62 fractional bits at 512-bit precision: (573/32 + 1)²
		"1e-78000": maxFunctionWork + 1, // saturates
	}
	for src, want := range cases {
		if got := numberFormatCost(literal(t, src)); got != want {
			f := literal(t, src).AsBigFloat()
			t.Errorf("numberFormatCost(%s) = %d, want %d (min prec %d, exp %d)", src, got, want, f.MinPrec(), f.MantExp(nil))
		}
	}
}

// TestSetBuildWithUnknownArgumentIsCharged: cty does not call a function whose argument is
// unknown, but decides its type first, and that converts (builds) the other arguments, so the
// type pass is charged. Uncharged, these loops built 128-element colliding sets for free.
func TestSetBuildWithUnknownArgumentIsCharged(t *testing.T) {
	t.Parallel()
	m := &ParsedModule{}
	arg := cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})
	got, err := m.functions(nil, nil)["setunion"].Call([]cty.Value{cty.UnknownVal(cty.Set(cty.String)), arg})
	if err != nil || got.IsKnown() || m.fnWork != 2*(1+5) {
		t.Fatalf("setunion(unknown, [a, b]) = %#v, %v, work %d; want unknown and 12 charged", got, err, m.fnWork)
	}
	vars := map[string]Variable{"u": {Value: cty.UnknownVal(cty.Set(cty.Number))}}
	nums := collidingNumbers(128)
	for _, expr := range []string{
		"[for i in range(1024) : setunion(var.u, " + nums + ")]",
		"[for i in range(1024) : can(setsubtract(" + nums + ", var.u))]",
		"[for i in range(1024) : setintersection(var.u, [[1e-10000]])]",
	} {
		m, got := evalLocal(t, expr, vars)
		if got.IsWhollyKnown() || !slices.Contains(diagCodes(m), DiagFunctionLimit) || m.fnWork != maxFunctionWork {
			t.Errorf("%.50s… = %#v, work %d, diagnostics %v; want the budget spent", expr, got, m.fnWork, m.Diagnostics)
		}
	}
}

// TestCompoundSetsRefuseCostlyNumbers: a set of tuples or objects is ordered by hash, so every
// later iteration formats its numbers again; a number that is costly to format is refused there.
func TestCompoundSetsRefuseCostlyNumbers(t *testing.T) {
	t.Parallel()
	for _, expr := range []string{`toset([[1e-400]])`, `setunion([{ a = 1e-400 }], [])`, `toset([[1, 2], [1e-400]])`} {
		m, got := evalLocal(t, expr, nil)
		if got.IsKnown() || !slices.Equal(diagCodes(m), []DiagCode{DiagFunctionLimit}) {
			t.Errorf("%s = %#v, diagnostics %v; want unknown with function_limit", expr, got, m.Diagnostics)
		}
	}
	// Ordinary numbers in compound sets, and costly numbers in sets of numbers, are fine.
	for _, expr := range []string{`length(toset([[0.1], [0.2], [1e-100]]))`, `length(toset([1e-400, 2e-400]))`} {
		m, got := evalLocal(t, expr, nil)
		if len(m.Diagnostics) != 0 || !got.IsKnown() {
			t.Errorf("%s = %#v, diagnostics %v; want known", expr, got, m.Diagnostics)
		}
	}
}

// TestSetBuildBudgetBoundary: toset(["a", "b"]) costs building the set in the type pass
// (2 elements × 5), then its argument (5), building the set again (10) and its result (7), and
// is refused with one unit less.
func TestSetBuildBudgetBoundary(t *testing.T) {
	t.Parallel()
	arg := cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})
	m := &ParsedModule{fnWork: maxFunctionWork - 32}
	if got, limited := boundedCall(t, m, "toset", arg); limited || got.LengthInt() != 2 || m.fnWork != maxFunctionWork {
		t.Errorf("toset with 32 work left = %#v (limited %v, work %d)", got, limited, m.fnWork)
	}
	m = &ParsedModule{fnWork: maxFunctionWork - 31}
	if got, limited := boundedCall(t, m, "toset", arg); !limited || got.IsKnown() {
		t.Errorf("toset with 31 work left = %#v (limited %v), want unknown", got, limited)
	}
}

// TestSetBuildTypeChecksBudget: the return type is decided before the call, and converting the
// arguments for it builds the set, so a call the budget refuses is not converted there either.
func TestSetBuildTypeChecksBudget(t *testing.T) {
	t.Parallel()
	m := &ParsedModule{fnWork: maxFunctionWork - 14}
	arg := cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})
	for _, name := range []string{"setunion", "distinct"} {
		ty, err := m.functions(nil, nil)[name].ReturnTypeForValues([]cty.Value{arg})
		if err != nil || ty != cty.DynamicPseudoType {
			t.Errorf("%s type with 14 work left = %#v, %v; want dynamic", name, ty, err)
		}
	}
	m.fnWork = maxFunctionWork - 15
	if ty, err := m.functions(nil, nil)["setunion"].ReturnTypeForValues([]cty.Value{arg}); err != nil || !ty.Equals(cty.Set(cty.String)) {
		t.Errorf("setunion type with 15 work left = %#v, %v; want set of string", ty, err)
	}
}

// TestSetFunctionsKeepSensitivity: a set built from a sensitive element is sensitive.
func TestSetFunctionsKeepSensitivity(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{"s": {Value: cty.StringVal("secret").Mark(SensitiveMark)}}
	for _, expr := range []string{
		`toset(["a", var.s])`,
		`distinct(["a", var.s])`,
		`setunion(["a"], [var.s])`,
		`setintersection(["a", var.s], ["a"])`,
		`setsubtract(["a"], [var.s])`,
	} {
		m, got := evalLocal(t, expr, vars)
		if len(m.Diagnostics) != 0 || !got.IsKnown() || !got.ContainsMarked() {
			t.Errorf("%s = %#v, diagnostics %v; want known and sensitive", expr, got, m.Diagnostics)
		}
	}
}

// TestRefusedCallsSpendWork: a call whose arguments are over the limit spends the work of
// measuring them, so refused calls cannot repeat for free.
func TestRefusedCallsSpendWork(t *testing.T) {
	t.Parallel()
	m := &ParsedModule{}
	big := cty.StringVal(strings.Repeat("x", maxFunctionValueSize))
	if _, limited := boundedCall(t, m, "upper", big); !limited || m.fnWork != maxFunctionValueSize {
		t.Errorf("upper over the limit: limited %v, work %d, want %d", limited, m.fnWork, maxFunctionValueSize)
	}
	m = &ParsedModule{fnWork: maxFunctionWork - 10}
	if _, limited := boundedCall(t, m, "upper", big); !limited || m.fnWork != maxFunctionWork {
		t.Errorf("upper with 10 work left: limited %v, work %d", limited, m.fnWork)
	}
}
