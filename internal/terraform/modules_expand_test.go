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

// instanceAddresses lists the instances' addresses, and of each evaluated one its resources'.
func instanceAddresses(instances []*terraform.ModuleInstance) (insts, resources []string) {
	for _, inst := range instances {
		insts = append(insts, inst.Address)
		for _, r := range inst.Resources {
			resources = append(resources, r.Address+" "+r.Module)
		}
	}
	return insts, resources
}

// diagCodesAt returns the codes of m's diagnostics on line.
func diagCodesAt(m *terraform.ParsedModule, line int) []terraform.DiagCode {
	var out []terraform.DiagCode
	for _, d := range m.Diagnostics {
		if d.Line == line {
			out = append(out, d.Code)
		}
	}
	return out
}

const echoModule = `variable "name" {
  default = "none"
}
resource "aws_vpc" "v" {
  name = var.name
}
output "id" {
  value = "${var.name}-id"
}
`

func TestModuleCallsExpandByCountAndForEach(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `module "c" {
  source = "./echo"
  count  = 2
  name   = "c${count.index}"
}
module "f" {
  source   = "./echo"
  for_each = { a = "x", b = "y" }
  name     = "${each.key}${each.value}"
}
module "zero" {
  source = "./echo"
  count  = 0
}
module "plain" {
  source = "./echo"
}
resource "aws_s3_bucket" "r" {
  all    = module.c[*].id
  second = module.c[1].id
  b      = module.f["b"].id
  keys   = keys(module.f)
  zero   = length(module.zero)
  plain  = module.plain.id
}
`,
		"echo/main.tf": echoModule,
	})
	instances := mustEvaluateTree(t, dir)
	insts, res := instanceAddresses(instances)
	wantInsts := []string{"", `module.c[0]`, `module.c[1]`, `module.f["a"]`, `module.f["b"]`, "module.plain"}
	if diff := cmp.Diff(wantInsts, insts); diff != "" {
		t.Errorf("instances (-want +got):\n%s", diff)
	}
	wantRes := []string{
		"aws_s3_bucket.r ",
		`module.c[0].aws_vpc.v module.c[0]`, `module.c[1].aws_vpc.v module.c[1]`,
		`module.f["a"].aws_vpc.v module.f["a"]`, `module.f["b"].aws_vpc.v module.f["b"]`,
		"module.plain.aws_vpc.v module.plain",
	}
	if diff := cmp.Diff(wantRes, res); diff != "" {
		t.Errorf("resources (-want +got):\n%s", diff)
	}
	root := instances[0]
	checks := map[string]cty.Value{
		"all":    cty.TupleVal([]cty.Value{cty.StringVal("c0-id"), cty.StringVal("c1-id")}),
		"second": cty.StringVal("c1-id"),
		"b":      cty.StringVal("by-id"),
		"keys":   cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")}),
		"zero":   cty.NumberIntVal(0),
		"plain":  cty.StringVal("none-id"),
	}
	for name, want := range checks {
		if got := resourceAttr(t, root, name); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", name, got, want)
		}
	}
	c1 := instance(t, instances, `module.c[1]`)
	if i, ok := c1.Key.Int(); !ok || i != 1 || c1.ExpansionUnknown || c1.Resources[0].CallRange.Start.Line != 1 {
		t.Errorf("module.c[1]: key %v, placeholder %v", c1.Key, c1.ExpansionUnknown)
	}
	if fb := instance(t, instances, `module.f["b"]`); func() bool { k, ok := fb.Key.Str(); return !ok || k != "b" }() {
		t.Errorf(`module.f["b"] key %v`, fb.Key)
	}
	if len(root.Module.Diagnostics) != 0 {
		t.Errorf("unexpected diagnostics: %v", diagLines(root.Module))
	}
}

func TestModuleCallsWithUnknownOrInvalidExpansion(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `module "u" {
  source = "./echo"
  count  = length(aws_x.list)
  name   = "u${count.index}"
}
module "both" {
  source   = "./echo"
  count    = 1
  for_each = {}
}
module "neg" {
  source = "./echo"
  count  = -1
}
resource "aws_s3_bucket" "r" {
  u = module.u
}
`,
		"echo/main.tf": echoModule,
	})
	instances := mustEvaluateTree(t, dir)
	insts, _ := instanceAddresses(instances)
	if diff := cmp.Diff([]string{"", "module.u[*]", "module.both[*]", "module.neg[*]"}, insts); diff != "" {
		t.Errorf("instances (-want +got):\n%s", diff)
	}
	u := instance(t, instances, "module.u[*]")
	if !u.ExpansionUnknown || !u.Key.IsNone() || u.Variables["name"].Value.IsKnown() {
		t.Errorf("placeholder: unknown %v, key %v, name %#v", u.ExpansionUnknown, u.Key, u.Variables["name"].Value)
	}
	if len(u.Resources) != 1 || u.Resources[0].Address != "module.u[*].aws_vpc.v" {
		t.Errorf("placeholder resources %v", u.Resources)
	}
	root := instances[0]
	if got := resourceAttr(t, root, "u"); got.IsKnown() {
		t.Errorf("module.u = %#v, want unknown", got)
	}
	for line, want := range map[int]terraform.DiagCode{
		3: terraform.DiagUnknownExpansion, 8: terraform.DiagInvalidExpansion, 13: terraform.DiagInvalidExpansion,
	} {
		if got := diagCodesAt(root.Module, line); !slices.Contains(got, want) {
			t.Errorf("line %d: diagnostics %v, want %s", line, got, want)
		}
	}
}

func TestNestedModuleExpansionAddresses(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `module "a" {
  source = "./mid"
  count  = 2
  label  = "a${count.index}"
}
`,
		"mid/main.tf": `variable "label" {}
module "b" {
  source   = "../echo"
  for_each = toset(["x", "y"])
  name     = "${var.label}-${each.key}"
}
output "names" {
  value = { for k, m in module.b : k => m.id }
}
`,
		"echo/main.tf": echoModule,
	})
	instances := mustEvaluateTree(t, dir)
	insts, _ := instanceAddresses(instances)
	want := []string{
		"", "module.a[0]", `module.a[0].module.b["x"]`, `module.a[0].module.b["y"]`,
		"module.a[1]", `module.a[1].module.b["x"]`, `module.a[1].module.b["y"]`,
	}
	if diff := cmp.Diff(want, insts); diff != "" {
		t.Errorf("instances (-want +got):\n%s", diff)
	}
	a1 := instance(t, instances, "module.a[1]")
	names := a1.Outputs["names"].Value
	if !names.GetAttr("y").RawEquals(cty.StringVal("a1-y-id")) {
		t.Errorf("module.a[1] names = %#v", names)
	}
	leaf := instance(t, instances, `module.a[1].module.b["y"]`)
	if leaf.Resources[0].Address != `module.a[1].module.b["y"].aws_vpc.v` {
		t.Errorf("leaf resource %q", leaf.Resources[0].Address)
	}
}

// One call has at most 10,000 instances, as a resource does; the tree has at most 10,000 module
// instances, so nested counts cannot multiply past it.
func TestModuleExpansionLimits(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		files     map[string]string
		instances int
	}{
		"per call": {map[string]string{
			"main.tf": "module \"m\" {\n  source = \"./leaf\"\n  count  = 20000\n}\n" +
				"resource \"aws_s3_bucket\" \"r\" {\n  n = length(module.m)\n}\n",
			"leaf/main.tf": "",
		}, 10_000},
		"tree": {map[string]string{
			"main.tf":      "module \"m\" {\n  source = \"./mid\"\n  count  = 200\n}\n",
			"mid/main.tf":  "module \"n\" {\n  source = \"../leaf\"\n  count  = 200\n}\n",
			"leaf/main.tf": "",
		}, 10_000},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			instances := mustEvaluateTree(t, files(t, tc.files))
			if got := len(instances) - 1; got != tc.instances {
				t.Errorf("%d module instances, want %d", got, tc.instances)
			}
			limited := false
			for _, inst := range instances {
				limited = limited || slices.ContainsFunc(inst.Module.Diagnostics, func(d terraform.Diagnostic) bool {
					return d.Code == terraform.DiagExpansionLimit
				})
			}
			if !limited {
				t.Error("no expansion_limit diagnostic")
			}
			// A cut expansion is unknown to the caller, never a partial tuple.
			if root := instances[0]; len(root.Resources) > 0 {
				if n := resourceAttr(t, root, "n"); n.IsKnown() {
					t.Errorf("length(module.m) = %#v, want unknown", n)
				}
			}
		})
	}
}

// Each instance evaluates the call's arguments again: their source is charged to the caller's
// expansion work (2^21 bytes), so a large input cannot be repeated 10,000 times.
func TestModuleExpansionChargesArgumentSource(t *testing.T) {
	t.Parallel()
	// About 250 KB of source with a value of size 1. The bound counts source bytes, so a cheap
	// expression proves it as well as the review's slow tuple, also under the race detector.
	big := "length(\"" + strings.Repeat("x", 249_990) + "\")"
	dir := files(t, map[string]string{
		"main.tf": "module \"m\" {\n  source = \"./leaf\"\n  count  = 100\n  x      = " + big + "\n}\n" +
			"resource \"aws_s3_bucket\" \"r\" {\n  n = length(module.m)\n}\n",
		"leaf/main.tf": "variable \"x\" {}\n",
	})
	instances := mustEvaluateTree(t, dir)
	// The first instance is free; 2^21 / 250,004 bytes allow 8 more.
	if got := len(instances) - 1; got != 9 {
		t.Errorf("%d instances, want 9", got)
	}
	root := instances[0]
	if got := diagCodesAt(root.Module, 1); !slices.Contains(got, terraform.DiagExpansionLimit) {
		t.Errorf("call diagnostics %v, want expansion_limit", got)
	}
	if n := resourceAttr(t, root, "n"); n.IsKnown() {
		t.Errorf("length(module.m) = %#v, want unknown", n)
	}
}

// The tree's module instance limit, at and just over it: a middle module and 9,999 leaves are
// 10,000 instances; 10,000 leaves pass the limit.
func TestModuleTreeInstanceLimitBoundary(t *testing.T) {
	t.Parallel()
	for count, limited := range map[int]bool{9_999: false, 10_000: true} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			t.Parallel()
			dir := files(t, map[string]string{
				"main.tf": "module \"mid\" {\n  source = \"./mid\"\n}\n" +
					"resource \"aws_s3_bucket\" \"r\" {\n  n = length(module.mid.all)\n}\n",
				"mid/main.tf": fmt.Sprintf("module \"leaf\" {\n  source = \"../leaf\"\n  count  = %d\n}\n", count) +
					"output \"all\" {\n  value = module.leaf\n}\n",
				"leaf/main.tf": "",
			})
			instances := mustEvaluateTree(t, dir)
			mid := instance(t, instances, "module.mid")
			gotLimited := slices.ContainsFunc(mid.Module.Diagnostics, func(d terraform.Diagnostic) bool {
				return d.Code == terraform.DiagExpansionLimit
			})
			n := resourceAttr(t, instances[0], "n")
			if gotLimited != limited || n.IsKnown() == limited {
				t.Errorf("limited %v, length known %v; want limited %v", gotLimited, n.IsKnown(), limited)
			}
			if !limited && !n.RawEquals(cty.NumberIntVal(int64(count))) {
				t.Errorf("length = %#v, want %d", n, count)
			}
		})
	}
}
