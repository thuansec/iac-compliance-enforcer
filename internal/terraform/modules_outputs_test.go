package terraform_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// instance returns the instance with address addr.
func instance(t *testing.T, instances []*terraform.ModuleInstance, addr string) *terraform.ModuleInstance {
	t.Helper()
	i := slices.IndexFunc(instances, func(inst *terraform.ModuleInstance) bool { return inst.Address == addr })
	if i < 0 {
		t.Fatalf("no instance %q", addr)
	}
	return instances[i]
}

// resourceAttr returns attribute name of the first resource of inst.
func resourceAttr(t *testing.T, inst *terraform.ModuleInstance, name string) cty.Value {
	t.Helper()
	if len(inst.Resources) == 0 {
		t.Fatalf("%q has no resources", inst.Address)
	}
	return inst.Resources[0].Value.GetAttr(name)
}

func TestModuleOutputsReachCallers(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `variable "token" {
  default   = "fake-token"
  sensitive = true
}
module "net" {
  source = "./net"
  prefix = "app"
  token  = var.token
}
module "gone" {
  source = "./missing"
}
resource "aws_s3_bucket" "b" {
  id       = module.net.id
  nested   = module.net.sub_name
  secret   = module.net.secret
  unknown  = module.net.res
  gone     = module.gone.anything
  uncalled = module.nothere.x
  whole    = module.net
  flagged  = module.net.flagged
  unflagged = module.net.unflagged
  dynamic  = module.net.dynamic_flag
  bad      = module.net.secret + 1
}
output "id" {
  value = module.net.id
}
`,
		"net/main.tf": `variable "prefix" {}
variable "token" {}
module "sub" {
  source = "./sub"
}
resource "aws_vpc" "v" {
  name = module.sub.name
}
output "id" {
  value = "${var.prefix}-id"
}
output "secret" {
  value     = var.token
  sensitive = true
}
output "res" {
  value = aws_vpc.v.id
}
output "sub_name" {
  value = module.sub.name
}
output "flagged" {
  value     = "plain"
  sensitive = true
}
output "unflagged" {
  value     = "plain"
  sensitive = false
}
output "dynamic_flag" {
  value     = "plain"
  sensitive = var.prefix == "app"
}
`,
		"net/sub/main.tf": `output "name" {
  value = "sub"
}
`,
	})
	instances := mustEvaluateTree(t, dir)
	root := instance(t, instances, "")
	checks := map[string]cty.Value{
		"id":        cty.StringVal("app-id"),
		"nested":    cty.StringVal("sub"),
		"secret":    cty.StringVal("fake-token").Mark(terraform.SensitiveMark),
		"unknown":   cty.DynamicVal,
		"gone":      cty.DynamicVal,
		"uncalled":  cty.DynamicVal,
		"flagged":   cty.StringVal("plain").Mark(terraform.SensitiveMark),
		"unflagged": cty.StringVal("plain"),
		// A sensitive argument that is not a constant is sensitive (fail closed).
		"dynamic": cty.StringVal("plain").Mark(terraform.SensitiveMark),
		// A failed evaluation over a sensitive output stays sensitive (fail closed).
		"bad": cty.DynamicVal.Mark(terraform.SensitiveMark),
	}
	for name, want := range checks {
		if got := resourceAttr(t, root, name); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", name, got, want)
		}
	}
	whole := resourceAttr(t, root, "whole")
	if !whole.Type().IsObjectType() || !whole.GetAttr("id").RawEquals(cty.StringVal("app-id")) {
		t.Errorf("whole = %#v, want the output object", whole)
	}
	if got := resourceAttr(t, instance(t, instances, "module.net"), "name"); !got.RawEquals(cty.StringVal("sub")) {
		t.Errorf("net's vpc name = %#v, want the sub output", got)
	}

	net := instance(t, instances, "module.net")
	var names []string
	for name := range net.Outputs {
		names = append(names, name)
	}
	slices.Sort(names)
	if diff := cmp.Diff([]string{"dynamic_flag", "flagged", "id", "res", "secret", "sub_name", "unflagged"}, names); diff != "" {
		t.Errorf("net outputs (-want +got):\n%s", diff)
	}
	if o := net.Outputs["secret"]; !o.Sensitive || !o.Value.IsMarked() || o.DeclRange.Start.Line != 12 {
		t.Errorf("secret output = %+v", o)
	}
	if o := net.Outputs["res"]; len(o.Unknown) != 1 || len(o.Unknown[0]) != 0 {
		t.Errorf("res output unknown paths = %v, want the whole value", o.Unknown)
	}
	if o := root.Outputs["id"]; !o.Value.RawEquals(cty.StringVal("app-id")) || o.Sensitive {
		t.Errorf("root output id = %+v", o)
	}
	// module.nothere is not called: unknown, with the evaluation warning hcl gives for an
	// attribute the module object does not have.
	if !slices.ContainsFunc(root.Module.Diagnostics, func(d terraform.Diagnostic) bool {
		return d.Code == terraform.DiagEvaluation && d.Line == 19
	}) {
		t.Errorf("no evaluation warning for module.nothere: %v", diagLines(root.Module))
	}
}

func TestModuleOutputsReportTerraformErrors(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `output "a" {
  description = "no value"
}
output "b" {
  value = 1
}
output "b" {
  value = 2
}
`,
	})
	root := mustEvaluateTree(t, dir)[0]
	want := []string{"main.tf:1 error missing_output_value", "main.tf:7 error duplicate_output"}
	if diff := cmp.Diff(want, diagLines(root.Module)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
	if v := root.Outputs["a"].Value; v.IsKnown() {
		t.Errorf("output without a value = %#v, want unknown", v)
	}
	if v := root.Outputs["b"].Value; !v.RawEquals(cty.NumberIntVal(1)) {
		t.Errorf("duplicate output = %#v, want the first", v)
	}
}

func TestModuleOutputsAreBounded(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": fmt.Sprintf("variable \"big\" {\n  default = %q\n}\noutput \"o\" {\n  value = var.big\n}\n",
			strings.Repeat("x", 300_000)),
	})
	root := mustEvaluateTree(t, dir)[0]
	if v := root.Outputs["o"].Value; v.IsKnown() {
		t.Error("an output over the value size limit is known")
	}
	if !slices.ContainsFunc(root.Module.Diagnostics, func(d terraform.Diagnostic) bool { return d.Code == terraform.DiagValueTooLarge }) {
		t.Errorf("no value_too_large: %v", diagLines(root.Module))
	}
}

// Skipped instances have unknown outputs: a caller past the tree budget sees module.x as unknown.
func TestModuleOutputsOfSkippedInstancesAreUnknown(t *testing.T) {
	t.Parallel()
	var root strings.Builder
	root.WriteString(fanOut(terraform.MaxModuleCalls, "./c"))
	fmt.Fprintf(&root, "resource \"aws_s3_bucket\" \"b\" {\n  first = module.c0.o\n  last  = module.c%d.o\n}\n", terraform.MaxModuleCalls-1)
	dir := files(t, map[string]string{
		"main.tf":   root.String(),
		"c/main.tf": heavyModule(200_000, 38) + "output \"o\" {\n  value = \"out\"\n}\n",
	})
	instances := mustEvaluateTree(t, dir)
	r := instances[0]
	if got := resourceAttr(t, r, "first"); !got.RawEquals(cty.StringVal("out")) {
		t.Errorf("first = %#v, want the evaluated output", got)
	}
	if got := resourceAttr(t, r, "last"); got.IsKnown() {
		t.Errorf("last = %#v, want unknown (skipped)", got)
	}
	// A skipped module is unknown as a whole, so naming its outputs is no evaluation error.
	if slices.ContainsFunc(r.Module.Diagnostics, func(d terraform.Diagnostic) bool { return d.Code == terraform.DiagEvaluation }) {
		t.Errorf("evaluation warning for a skipped module's output: %v", diagLines(r.Module))
	}
}
