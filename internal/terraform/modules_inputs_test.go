package terraform_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// childVariables loads the tree of dir, evaluates the root's variables and locals, and returns
// the variables of the child that the root's call name loads, evaluated from the call's inputs
// in a fresh instance of the child, with that instance and the root.
func childVariables(t *testing.T, dir, name string) (vars map[string]terraform.Variable, child, root *terraform.ParsedModule) {
	t.Helper()
	ctx := context.Background()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	limits := terraform.DefaultLimits()
	d, err := terraform.Discover(ctx, r, limits)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := terraform.LoadModuleTree(ctx, r, d, ".", limits, terraform.TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	root = tree.Root.Module
	rootVars, err := root.EvaluateVariables(ctx, r, terraform.VarOptions{}, limits)
	if err != nil {
		t.Fatal(err)
	}
	locals, err := root.EvaluateLocals(ctx, rootVars)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(tree.Root.Calls, func(c *terraform.ModuleCall) bool { return c.Name == name })
	if i < 0 || tree.Root.Calls[i].Child == nil {
		t.Fatalf("no resolved call %q", name)
	}
	call := tree.Root.Calls[i]
	inputs, err := root.ModuleInputs(ctx, call, rootVars, locals)
	if err != nil {
		t.Fatalf("ModuleInputs: %v", err)
	}
	child = call.Child.Module.NewInstance()
	vars, err = child.EvaluateModuleVariables(ctx, call, inputs)
	if err != nil {
		t.Fatalf("EvaluateModuleVariables: %v", err)
	}
	return vars, child, root
}

// diagLines returns the diagnostics of m as "file:line severity code".
func diagLines(m *terraform.ParsedModule) []string {
	var out []string
	for _, d := range m.Diagnostics {
		out = append(out, fmt.Sprintf("%s:%d %s %s", d.File, d.Line, d.Severity, d.Code))
	}
	return out
}

func TestModuleInputsBecomeChildVariables(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `
variable "env" {
  default = "prod"
}
variable "token" {
  default   = "fake-token"
  sensitive = true
}
locals {
  name = "app-${var.env}"
}
module "net" {
  source     = "./net"
  version    = "1.0.0"
  count      = 1
  for_each   = {}
  providers  = { aws = aws.eu }
  depends_on = [aws_s3_bucket.b]

  name      = local.name
  ports     = [80, "443"]
  secret    = var.token
  typed     = var.token
  secrets   = [var.token, "other"]
  plain     = "visible"
  cfg       = { size = 2 }
  from_res  = aws_s3_bucket.b.id
  from_mod  = module.other.id
  nul       = null
  strict    = null
}
`,
		"net/variables.tf": `
variable "name" {
  type = string
}
variable "ports" {
  type = list(number)
}
variable "secret" {}
variable "typed" {
  type = string
}
variable "secrets" {
  type = list(string)
}
variable "plain" {
  sensitive = true
}
variable "cfg" {
  type = object({ size = number, tier = optional(string, "standard") })
}
variable "from_res" {}
variable "from_mod" {}
variable "nul" {
  default = "kept-null"
}
variable "strict" {
  default  = "fallback"
  nullable = false
}
variable "absent" {
  default = "the-default"
}
`,
	})
	vars, child, _ := childVariables(t, dir, "net")
	want := map[string]cty.Value{
		"name":   cty.StringVal("app-prod"),
		"ports":  cty.ListVal([]cty.Value{cty.NumberIntVal(80), cty.NumberIntVal(443)}),
		"secret": cty.StringVal("fake-token").Mark(terraform.SensitiveMark),
		"typed":  cty.StringVal("fake-token").Mark(terraform.SensitiveMark),
		// Conversion can reshape a value, so its marks cover the whole value (fail closed).
		"secrets":  cty.ListVal([]cty.Value{cty.StringVal("fake-token"), cty.StringVal("other")}).Mark(terraform.SensitiveMark),
		"plain":    cty.StringVal("visible").Mark(terraform.SensitiveMark),
		"cfg":      cty.ObjectVal(map[string]cty.Value{"size": cty.NumberIntVal(2), "tier": cty.StringVal("standard")}),
		"from_res": cty.DynamicVal,
		"from_mod": cty.DynamicVal,
		"nul":      cty.NullVal(cty.DynamicPseudoType),
		"strict":   cty.StringVal("fallback"),
		"absent":   cty.StringVal("the-default"),
	}
	if len(vars) != len(want) {
		t.Errorf("got %d variables, want %d", len(vars), len(want))
	}
	for name, w := range want {
		v, ok := vars[name]
		if !ok {
			t.Errorf("variable %q missing", name)
			continue
		}
		if !v.Value.RawEquals(w) {
			t.Errorf("%s = %#v, want %#v", name, v.Value, w)
		}
	}
	if !vars["plain"].Sensitive || vars["secret"].Sensitive {
		t.Errorf("declared sensitivity: plain %v, secret %v; want true, false", vars["plain"].Sensitive, vars["secret"].Sensitive)
	}
	if len(child.Diagnostics) != 0 {
		t.Errorf("unexpected diagnostics: %v", diagLines(child))
	}
}

func TestModuleInputsReportTerraformErrors(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `module "net" {
  source = "./net"
  extra  = "x"
  port   = "not-a-number"
}
`,
		"net/main.tf": `variable "required" {}
variable "port" {
  type = number
}
`,
	})
	vars, child, _ := childVariables(t, dir, "net")
	if v := vars["required"].Value; v.IsKnown() {
		t.Errorf("missing required input = %#v, want unknown", v)
	}
	if v := vars["port"].Value; !v.RawEquals(cty.StringVal("not-a-number")) {
		t.Errorf("mismatched input = %#v, want it kept unconverted", v)
	}
	want := []string{
		"main.tf:1 error missing_module_input",
		"main.tf:3 error undeclared_module_input",
		"main.tf:4 warning variable_type",
	}
	if diff := cmp.Diff(want, diagLines(child)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
	if !child.HasErrors() {
		t.Error("child instance has no errors")
	}
}

func TestModuleInputsInJSONAndBlocks(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf.json": `{"variable": {"env": {"default": "dev"}},
 "module": {"net": {"source": "./net", "count": 1, "name": "app-${var.env}"}}}`,
		"net/main.tf": `variable "name" {}`,
	})
	vars, child, _ := childVariables(t, dir, "net")
	if v := vars["name"].Value; !v.RawEquals(cty.StringVal("app-dev")) {
		t.Errorf("name = %#v, want app-dev", v)
	}
	if len(child.Diagnostics) != 0 {
		t.Errorf("unexpected diagnostics: %v", diagLines(child))
	}

	dir = files(t, map[string]string{
		"main.tf":     "module \"net\" {\n  source = \"./net\"\n  nested {\n  }\n}\n",
		"net/main.tf": "",
	})
	ctx := context.Background()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	d, err := terraform.Discover(ctx, r, terraform.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	tree, err := terraform.LoadModuleTree(ctx, r, d, ".", terraform.DefaultLimits(), terraform.TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root.Module
	if _, err := root.ModuleInputs(ctx, tree.Root.Calls[0], nil, nil); err != nil {
		t.Fatal(err)
	}
	if !root.HasErrors() {
		t.Errorf("a block inside a module call is not an error: %v", diagLines(root))
	}
}

func TestModuleInputsAreBounded(t *testing.T) {
	t.Parallel()
	// maxLocalValueSize is 2^18 units: one per value plus one per string byte.
	// A string of n bytes is n+1 units, and the estimate adds the expression's source bytes.
	for width, known := range map[int]bool{100_000: true, 1<<18 - 64: true, 1 << 18: false, 300_000: false} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			t.Parallel()
			dir := files(t, map[string]string{
				"main.tf": fmt.Sprintf("variable \"big\" {\n  default = %q\n}\n", strings.Repeat("x", width)) +
					"module \"net\" {\n  source = \"./net\"\n  big    = var.big\n}\n",
				"net/main.tf": `variable "big" {}`,
			})
			vars, _, root := childVariables(t, dir, "net")
			if got := vars["big"].Value.IsKnown(); got != known {
				t.Errorf("input of %d bytes known = %v, want %v", width, got, known)
			}
			tooLarge := slices.ContainsFunc(root.Diagnostics, func(d terraform.Diagnostic) bool {
				return d.Code == terraform.DiagValueTooLarge
			})
			if tooLarge == known {
				t.Errorf("value_too_large reported = %v, want %v: %v", tooLarge, !known, diagLines(root))
			}
		})
	}
}

// Two instances of one parse evaluate in their own state: a diagnostic raised in one never
// reaches the other, nor the shared parse.
func TestModuleInstancesHaveTheirOwnState(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": module("a", "./net") + module("b", "./net"),
		"net/main.tf": `variable "v" {
  default = "x"
}
locals {
  bad = upper(1, 2)
}
`,
	})
	ctx := context.Background()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	d, err := terraform.Discover(ctx, r, terraform.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	tree, err := terraform.LoadModuleTree(ctx, r, d, ".", terraform.DefaultLimits(), terraform.TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	parse := tree.Root.Calls[0].Child.Module
	if parse != tree.Root.Calls[1].Child.Module {
		t.Fatal("the two calls do not share a parse")
	}
	before := len(parse.Diagnostics)
	a, b := parse.NewInstance(), parse.NewInstance()
	if a.Dir != "net" || len(a.Blocks) != len(parse.Blocks) {
		t.Errorf("instance: dir %q, %d blocks", a.Dir, len(a.Blocks))
	}
	vars, err := a.EvaluateModuleVariables(ctx, tree.Root.Calls[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.EvaluateLocals(ctx, vars); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(a.Diagnostics, func(d terraform.Diagnostic) bool { return d.Code == terraform.DiagEvaluation }) {
		t.Errorf("instance a has no evaluation diagnostic: %v", diagLines(a))
	}
	if len(b.Diagnostics) != 0 || len(parse.Diagnostics) != before {
		t.Errorf("diagnostics leaked: b %v, parse %d → %d", diagLines(b), before, len(parse.Diagnostics))
	}
	if strings.Contains(fmt.Sprint(diagLines(a)), "fake") {
		t.Error("a diagnostic quotes a value")
	}
}

// The inputs of one call share maxResourcesSize (2^22 units): each of 20 inputs of 2^18-64 bytes
// fits on its own, and the inputs past the total are unknown.
func TestModuleInputsShareTheTotalLimit(t *testing.T) {
	t.Parallel()
	var call, decl strings.Builder
	fmt.Fprintf(&call, "variable \"big\" {\n  default = %q\n}\nmodule \"net\" {\n  source = \"./net\"\n", strings.Repeat("x", 1<<18-64))
	for i := range 20 {
		fmt.Fprintf(&call, "  in%02d = var.big\n", i)
		fmt.Fprintf(&decl, "variable \"in%02d\" {}\n", i)
	}
	call.WriteString("}\n")
	vars, _, root := childVariables(t, files(t, map[string]string{"main.tf": call.String(), "net/main.tf": decl.String()}), "net")
	known := 0
	for _, v := range vars {
		if v.Value.IsKnown() {
			known++
		}
	}
	if known != 16 {
		t.Errorf("%d inputs known, want 16 (2^22 / 2^18)", known)
	}
	if !slices.ContainsFunc(root.Diagnostics, func(d terraform.Diagnostic) bool { return d.Code == terraform.DiagValueTooLarge }) {
		t.Errorf("no value_too_large diagnostic: %v", diagLines(root))
	}
}

func TestModuleInputsHonourCancellation(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{"main.tf": module("net", "./net"), "net/main.tf": `variable "v" {}`})
	ctx := context.Background()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	d, err := terraform.Discover(ctx, r, terraform.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	tree, err := terraform.LoadModuleTree(ctx, r, d, ".", terraform.DefaultLimits(), terraform.TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	call := tree.Root.Calls[0]
	inputs := map[string]terraform.Input{"v": {Value: cty.StringVal("x")}}
	if _, err := tree.Root.Module.ModuleInputs(cancelled, call, nil, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("ModuleInputs: err = %v, want context.Canceled", err)
	}
	if _, err := call.Child.Module.NewInstance().EvaluateModuleVariables(cancelled, call, inputs); !errors.Is(err, context.Canceled) {
		t.Errorf("EvaluateModuleVariables: err = %v, want context.Canceled", err)
	}
}
