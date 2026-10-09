package terraform_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

func evaluateTree(ctx context.Context, t *testing.T, dir string) ([]*terraform.ModuleInstance, error) {
	t.Helper()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	limits := terraform.DefaultLimits()
	// Loading runs even when ctx is cancelled, so only EvaluateTree sees the cancellation.
	load := context.WithoutCancel(ctx)
	d, err := terraform.Discover(load, r, limits)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := terraform.LoadModuleTree(load, r, d, ".", limits)
	if err != nil {
		t.Fatal(err)
	}
	return terraform.EvaluateTree(ctx, r, tree, terraform.VarOptions{}, limits)
}

func mustEvaluateTree(t *testing.T, dir string) []*terraform.ModuleInstance {
	t.Helper()
	instances, err := evaluateTree(context.Background(), t, dir)
	if err != nil {
		t.Fatalf("EvaluateTree: %v", err)
	}
	return instances
}

// resourceValues lists every resource of the instances as "address module call-file:line = attr".
func resourceValues(instances []*terraform.ModuleInstance, attr string) []string {
	var out []string
	for _, inst := range instances {
		for _, r := range inst.Resources {
			v := "?"
			if r.Value.IsKnown() && r.Value.Type().IsObjectType() && r.Value.Type().HasAttribute(attr) {
				if a := r.Value.GetAttr(attr); a.IsKnown() && a.Type() == cty.String {
					v = a.AsString()
				}
			}
			out = append(out, fmt.Sprintf("%s [%s] %s:%d = %s", r.Address, r.Module, r.CallFile, r.CallRange.Start.Line, v))
		}
	}
	return out
}

func TestEvaluateTreeFlowsInputsThroughInstances(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `variable "env" {
  default = "prod"
}
resource "aws_vpc" "v" {
  name = var.env
}
module "net" {
  source = "./net"
  prefix = "app-${var.env}"
}
module "net2" {
  source = "./net"
  prefix = "other"
}
module "gone" {
  source = "./missing"
}
`,
		"net/main.tf": `variable "prefix" {}
locals {
  name = "${var.prefix}-subnet"
}
resource "aws_subnet" "s" {
  name = local.name
}
module "sub" {
  source = "./sub"
  label  = local.name
}
`,
		"net/sub/main.tf": `variable "label" {
  type = string
}
resource "aws_instance" "i" {
  count = 2
  name  = "${var.label}-${count.index}"
}
`,
	})
	instances := mustEvaluateTree(t, dir)
	var addrs []string
	for _, inst := range instances {
		addrs = append(addrs, inst.Address+" "+inst.Dir)
	}
	want := []string{" .", "module.net net", "module.net.module.sub net/sub", "module.net2 net", "module.net2.module.sub net/sub"}
	if diff := cmp.Diff(want, addrs); diff != "" {
		t.Errorf("instances (-want +got):\n%s", diff)
	}
	wantRes := []string{
		"aws_vpc.v [] :0 = prod",
		"module.net.aws_subnet.s [module.net] main.tf:7 = app-prod-subnet",
		"module.net.module.sub.aws_instance.i[0] [module.net.module.sub] net/main.tf:8 = app-prod-subnet-0",
		"module.net.module.sub.aws_instance.i[1] [module.net.module.sub] net/main.tf:8 = app-prod-subnet-1",
		"module.net2.aws_subnet.s [module.net2] main.tf:11 = other-subnet",
		"module.net2.module.sub.aws_instance.i[0] [module.net2.module.sub] net/main.tf:8 = other-subnet-0",
		"module.net2.module.sub.aws_instance.i[1] [module.net2.module.sub] net/main.tf:8 = other-subnet-1",
	}
	if diff := cmp.Diff(wantRes, resourceValues(instances, "name")); diff != "" {
		t.Errorf("resources (-want +got):\n%s", diff)
	}
	sub := instances[2]
	if r := sub.Resources[0]; r.BaseAddress != "module.net.module.sub.aws_instance.i" || r.Name != "i" {
		t.Errorf("base address %q, name %q", r.BaseAddress, r.Name)
	}
	if v := sub.Variables["label"].Value; !v.RawEquals(cty.StringVal("app-prod-subnet")) {
		t.Errorf("sub label = %#v", v)
	}
	if instances[1].Call == nil || instances[1].Call.Name != "net" || instances[0].Call != nil {
		t.Error("instance calls are not recorded")
	}
	for _, inst := range instances {
		if inst.Skipped || len(inst.Module.Diagnostics) != 0 {
			t.Errorf("%s: skipped %v, diagnostics %v", inst.Address, inst.Skipped, diagLines(inst.Module))
		}
	}
	if instances[1].Module == instances[3].Module {
		t.Error("two calls to one directory share an instance")
	}
}

// heavyModule is a module whose instances each read a large variable default (source work) and
// pass it through functions (function work).
func heavyModule(bytes, calls int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "variable \"big\" {\n  default = %q\n}\nlocals {\n", strings.Repeat("x", bytes))
	for i := range calls {
		fmt.Fprintf(&b, "  u%d = upper(var.big)\n", i)
	}
	b.WriteString("}\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"fixed\"\n}\n")
	return b.String()
}

func fanOut(n int, source string) string {
	var b strings.Builder
	for i := range n {
		b.WriteString(module(fmt.Sprintf("c%d", i), source))
	}
	return b.String()
}

// countSkipped returns how many instances were evaluated and skipped, and whether every
// skipped one has a module_work_limit warning on its caller.
func countSkipped(instances []*terraform.ModuleInstance) (evaluated, skipped int, warned bool) {
	warned = true
	for _, inst := range instances {
		if !inst.Skipped {
			evaluated++
			continue
		}
		skipped++
		if inst.Resources != nil || inst.Variables != nil {
			warned = false
		}
	}
	root := instances[0].Module
	if skipped > 0 && !slices.ContainsFunc(root.Diagnostics, func(d terraform.Diagnostic) bool {
		return d.Code == terraform.DiagModuleWorkLimit
	}) {
		warned = false
	}
	return evaluated, skipped, warned
}

// A fan-out of 1,000 calls to a module that reads 200 KB of source and charges about 8M units
// of function work per instance would take minutes: the tree budget evaluates a few instances
// and skips the rest with a warning.
func TestEvaluateTreeBoundsTheWholeTree(t *testing.T) {
	t.Parallel()
	// Each instance of "source" re-reads 200 KB (8 MiB tree budget: about 42 instances), and
	// each instance of "function" charges 38 × 200 KB of function work (2^23: 2 instances).
	for name, tc := range map[string]struct {
		mod          string
		maxEvaluated int
	}{
		"source":   {heavyModule(200_000, 0), 44},
		"function": {heavyModule(200_000, 38), 5},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := files(t, map[string]string{
				"main.tf":   fanOut(terraform.MaxModuleCalls, "./c"),
				"c/main.tf": tc.mod,
			})
			start := time.Now()
			instances := mustEvaluateTree(t, dir)
			elapsed := time.Since(start)
			evaluated, skipped, warned := countSkipped(instances)
			if len(instances) != terraform.MaxModuleCalls+1 || evaluated < 2 || evaluated > tc.maxEvaluated || !warned {
				t.Errorf("%d instances: %d evaluated, %d skipped, warned %v; want 2 to %d evaluated and the rest skipped with a warning",
					len(instances), evaluated, skipped, warned, tc.maxEvaluated)
			}
			if elapsed > 20*time.Second {
				t.Errorf("took %v", elapsed)
			}
		})
	}
}

// Small modules stay well inside the tree budget: 1,000 instances are all evaluated.
func TestEvaluateTreeEvaluatesManySmallInstances(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":   fanOut(terraform.MaxModuleCalls, "./c"),
		"c/main.tf": `resource "aws_s3_bucket" "b" {}`,
	})
	instances := mustEvaluateTree(t, dir)
	evaluated, skipped, _ := countSkipped(instances)
	if evaluated != terraform.MaxModuleCalls+1 || skipped != 0 {
		t.Errorf("%d evaluated, %d skipped; want all %d", evaluated, skipped, terraform.MaxModuleCalls+1)
	}
}

// The inputs of all calls of one caller share one size budget (2^22 units): 1,000 calls passing
// a 200 KB value cannot hold 200 MB of inputs.
func TestEvaluateTreeBoundsInputsPerCaller(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	fmt.Fprintf(&b, "variable \"big\" {\n  default = %q\n}\n", strings.Repeat("x", 200_000))
	for i := range 100 {
		fmt.Fprintf(&b, "module \"c%d\" {\n  source = \"./c\"\n  v      = var.big\n}\n", i)
	}
	dir := files(t, map[string]string{
		"main.tf":   b.String(),
		"c/main.tf": `variable "v" {}`,
	})
	known := 0
	for _, inst := range mustEvaluateTree(t, dir) {
		if v, ok := inst.Variables["v"]; ok && v.Value.IsKnown() {
			known++
		}
	}
	// 2^22 / 200,001 units: 20 inputs fit.
	if known != 20 {
		t.Errorf("%d known inputs, want 20", known)
	}
}

func TestEvaluateTreeHonoursCancellation(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{"main.tf": module("a", "./a"), "a/main.tf": ""})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := evaluateTree(ctx, t, dir); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// A caller's work on its calls' inputs counts toward the tree: six modules each passing 200 KB
// to 20 children hold 24M units of inputs, past the tree's 2^22 input budget.
func TestEvaluateTreeChargesCallersForInputs(t *testing.T) {
	t.Parallel()
	var mid strings.Builder
	fmt.Fprintf(&mid, "variable \"big\" {\n  default = %q\n}\n", strings.Repeat("x", 200_000))
	for i := range 20 {
		fmt.Fprintf(&mid, "module \"l%d\" {\n  source = \"../leaf\"\n  v      = var.big\n}\n", i)
	}
	dir := files(t, map[string]string{
		"main.tf":      fanOut(6, "./mid"),
		"mid/main.tf":  mid.String(),
		"leaf/main.tf": `variable "v" {}`,
	})
	instances := mustEvaluateTree(t, dir)
	evaluated, skipped, warned := countSkipped(instances)
	if skipped == 0 || !warned {
		t.Errorf("%d evaluated, %d skipped, warned %v; want inputs to use up the tree budget", evaluated, skipped, warned)
	}
}

// The root is always evaluated and not charged to the tree's source budget: a root of more than
// 8 MiB still has its children evaluated.
func TestEvaluateTreeDoesNotChargeTheRootSource(t *testing.T) {
	t.Parallel()
	big := func(name string) string {
		return fmt.Sprintf("variable %q {\n  default = %q\n}\n", name, strings.Repeat("x", 4_400_000))
	}
	dir := files(t, map[string]string{
		"a.tf":      big("a"),
		"b.tf":      big("b"),
		"main.tf":   module("c", "./c"),
		"c/main.tf": `resource "aws_s3_bucket" "b" {}`,
	})
	instances := mustEvaluateTree(t, dir)
	if len(instances) != 2 || instances[1].Skipped {
		t.Errorf("child of a large root skipped: %d instances", len(instances))
	}
}
