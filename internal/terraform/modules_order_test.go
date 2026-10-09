package terraform_test

import (
	"slices"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

func TestModuleOutputsFlowIntoLocalsAndInputs(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		// b is declared before a but uses a's output; q uses a's output and feeds c.
		"main.tf": `variable "token" {
  default   = "fake-token"
  sensitive = true
}
locals {
  p      = "start"
  q      = "${module.a.out}-q"
  secret = module.a.secret
  bad    = module.a.secret + 1
}
module "b" {
  source = "./echo"
  in     = module.a.out
}
module "a" {
  source = "./echo"
  in     = local.p
  secret = var.token
}
module "c" {
  source = "./echo"
  in     = local.q
}
resource "aws_s3_bucket" "r" {
  b      = module.b.out
  c      = module.c.out
  secret = local.secret
}
`,
		"echo/main.tf": `variable "in" {}
variable "secret" {
  default = "none"
}
output "out" {
  value = "${var.in}!"
}
output "secret" {
  value = var.secret
}
`,
	})
	instances := mustEvaluateTree(t, dir)
	root := instances[0]
	want := map[string]cty.Value{
		"b":      cty.StringVal("start!!"),
		"c":      cty.StringVal("start!-q!"),
		"secret": cty.StringVal("fake-token").Mark(terraform.SensitiveMark),
	}
	for name, w := range want {
		if got := resourceAttr(t, root, name); !got.RawEquals(w) {
			t.Errorf("%s = %#v, want %#v", name, got, w)
		}
	}
	if got := root.Locals["q"].Value; !got.RawEquals(cty.StringVal("start!-q")) {
		t.Errorf("local.q = %#v", got)
	}
	// A failed local over a sensitive output stays sensitive (fail closed).
	if got := root.Locals["bad"].Value; !got.RawEquals(cty.DynamicVal.Mark(terraform.SensitiveMark)) {
		t.Errorf("local.bad = %#v, want sensitive unknown", got)
	}
	if refs := root.Locals["q"].References; !slices.Contains(refs, "module.a") {
		t.Errorf("local.q references %v, want module.a", refs)
	}
	// Instances are listed in the order they start: the dependency order.
	var addrs []string
	for _, inst := range instances {
		addrs = append(addrs, inst.Address)
	}
	if !slices.Equal(addrs, []string{"", "module.a", "module.b", "module.c"}) {
		t.Errorf("instances %v", addrs)
	}
	if got := diagLines(root.Module); !slices.Equal(got, []string{"main.tf:9 warning evaluation"}) {
		t.Errorf("diagnostics %v, want only local.bad's evaluation warning", got)
	}
}

func TestCyclesThroughModuleCallsAreUnknown(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `locals {
  c = module.m.out
}
module "m" {
  source = "./echo"
  in     = local.c
}
module "self" {
  source = "./echo"
  in     = module.self.out
}
resource "aws_s3_bucket" "r" {
  c = local.c
  m = module.m.out
  k = module.m.const
}
`,
		"echo/main.tf": `variable "in" {}
output "out" {
  value = "${var.in}!"
}
output "const" {
  value = "c"
}
resource "aws_vpc" "v" {
  name = "fixed"
}
`,
	})
	instances := mustEvaluateTree(t, dir)
	root := instances[0]
	// Every output of a module in a cycle is unknown, even one that does not use the cycle.
	for _, name := range []string{"c", "m", "k"} {
		if got := resourceAttr(t, root, name); got.IsKnown() {
			t.Errorf("%s = %#v, want unknown (cycle)", name, got)
		}
	}
	want := []string{"main.tf:2 warning local_cycle", "main.tf:4 warning module_cycle", "main.tf:8 warning module_cycle"}
	if got := diagLines(root.Module); !slices.Equal(got, want) {
		t.Errorf("diagnostics %v, want %v", got, want)
	}
	// The modules in a cycle are still evaluated: their resources are checked.
	m := instance(t, instances, "module.m")
	if m.Skipped || len(m.Resources) != 1 || m.Variables["in"].Value.IsKnown() {
		t.Errorf("module.m: skipped %v, %d resources, in = %#v", m.Skipped, len(m.Resources), m.Variables["in"].Value)
	}
}

// Locals see module.<name> only for names the module calls; another name is unknown with an
// evaluation warning, as in resources.
func TestLocalsSeeOnlyCalledModules(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `locals {
  x = module.nothere.out
  y = module.gone.out
}
module "gone" {
  source = "./missing"
}
`,
	})
	root := mustEvaluateTree(t, dir)[0]
	if root.Locals["x"].Value.IsKnown() || root.Locals["y"].Value.IsKnown() {
		t.Errorf("x = %#v, y = %#v, want unknown", root.Locals["x"].Value, root.Locals["y"].Value)
	}
	if !slices.ContainsFunc(root.Module.Diagnostics, func(d terraform.Diagnostic) bool {
		return d.Code == terraform.DiagEvaluation && d.Line == 2
	}) {
		t.Errorf("no evaluation warning for module.nothere: %v", diagLines(root.Module))
	}
}

func TestCyclesOfModuleCallsAreUnknown(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `module "a" {
  source = "./echo"
  in     = module.b.out
}
module "b" {
  source = "./echo"
  in     = module.a.out
}
resource "aws_s3_bucket" "r" {
  a = module.a.const
  b = module.b.const
}
`,
		"echo/main.tf": `variable "in" {}
output "out" {
  value = "${var.in}!"
}
output "const" {
  value = "c"
}
resource "aws_vpc" "v" {}
`,
	})
	instances := mustEvaluateTree(t, dir)
	root := instances[0]
	want := []string{"main.tf:1 warning module_cycle", "main.tf:5 warning module_cycle"}
	if got := diagLines(root.Module); !slices.Equal(got, want) {
		t.Errorf("diagnostics %v, want %v", got, want)
	}
	for _, name := range []string{"a", "b"} {
		if got := resourceAttr(t, root, name); got.IsKnown() {
			t.Errorf("%s = %#v, want unknown (cycle)", name, got)
		}
		inst := instance(t, instances, "module."+name)
		if inst.Skipped || len(inst.Resources) != 1 || inst.Variables["in"].Value.IsKnown() {
			t.Errorf("module.%s: skipped %v, %d resources, in = %#v",
				name, inst.Skipped, len(inst.Resources), inst.Variables["in"].Value)
		}
	}
}
