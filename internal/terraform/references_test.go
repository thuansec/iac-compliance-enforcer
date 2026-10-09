package terraform_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// resourceRefs returns the references of the resource with address addr in instances.
func resourceRefs(t *testing.T, instances []*terraform.ModuleInstance, addr string) (*terraform.Resource, map[string][]string) {
	t.Helper()
	for _, inst := range instances {
		for i := range inst.Resources {
			if r := &inst.Resources[i]; r.Address == addr {
				return r, r.References
			}
		}
	}
	t.Fatalf("no resource %q", addr)
	return nil, nil
}

func TestAttributeReferences(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `locals {
  logs = aws_s3_bucket.logs.id
  both = [local.logs, data.aws_iam_policy_document.p.json]
}
resource "aws_s3_bucket" "logs" {}
resource "aws_s3_bucket" "b" {
  bucket   = aws_s3_bucket.logs.id
  indexed  = aws_subnet.private[0].id
  keyed    = aws_subnet.byname["a"].id
  splat    = aws_subnet.many[*].id
  dynamic  = aws_subnet.private[var.i].id
  through  = local.both
  module   = module.net.vpc_id
  literal  = "x"
  logging {
    target_bucket = aws_s3_bucket.logs.id
  }
  depends_on = [aws_s3_bucket.logs]
}
module "net" {
  source = "./net"
  cidr   = aws_vpc_ipam_pool.p.id
}
output "o" {
  value = aws_s3_bucket.logs.arn
}
`,
		"net/main.tf": `variable "cidr" {}
locals {
  c = var.cidr
}
resource "aws_vpc" "v" {
  cidr_block = local.c
  peer       = aws_vpc.other.id
  direct     = var.cidr
  depends_on = [aws_vpc.other]
}
resource "aws_vpc" "other" {}
output "vpc_id" {
  value = aws_vpc.v.id
}
`,
	})
	instances := mustEvaluateTree(t, dir)
	_, got := resourceRefs(t, instances, "aws_s3_bucket.b")
	want := map[string][]string{
		"bucket":                  {"aws_s3_bucket.logs"},
		"indexed":                 {"aws_subnet.private[0]"},
		"keyed":                   {`aws_subnet.byname["a"]`},
		"splat":                   {"aws_subnet.many"},
		"dynamic":                 {"aws_subnet.private"},
		"through":                 {"aws_s3_bucket.logs", "data.aws_iam_policy_document.p"},
		"module":                  {"module.net"},
		"logging.0.target_bucket": {"aws_s3_bucket.logs"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("root references (-want +got):\n%s", diff)
	}

	child, got := resourceRefs(t, instances, "module.net.aws_vpc.v")
	want = map[string][]string{
		// Through a local and a module input: the caller's qualification is kept.
		"cidr_block": {"aws_vpc_ipam_pool.p"},
		"direct":     {"aws_vpc_ipam_pool.p"},
		"peer":       {"module.net.aws_vpc.other"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("child references (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"module.net.aws_vpc.other"}, child.DependsOn); diff != "" {
		t.Errorf("child depends_on (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"aws_s3_bucket.logs"}, instances[0].Outputs["o"].References); diff != "" {
		t.Errorf("output references (-want +got):\n%s", diff)
	}
	net := instance(t, instances, "module.net")
	if diff := cmp.Diff([]string{"module.net.aws_vpc.v"}, net.Outputs["vpc_id"].References); diff != "" {
		t.Errorf("child output references (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"aws_vpc_ipam_pool.p"}, net.Locals["c"].References); diff != "" {
		t.Errorf("child local references (-want +got):\n%s", diff)
	}
}

// Instances of a count module qualify their references with their own key.
func TestReferencesInExpandedModules(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":   "module \"m\" {\n  source = \"./m\"\n  count  = 2\n}\n",
		"m/main.tf": "resource \"aws_s3_bucket\" \"a\" {}\nresource \"aws_s3_bucket\" \"b\" {\n  x = aws_s3_bucket.a.id\n}\n",
	})
	instances := mustEvaluateTree(t, dir)
	_, got := resourceRefs(t, instances, "module.m[1].aws_s3_bucket.b")
	if diff := cmp.Diff(map[string][]string{"x": {"module.m[1].aws_s3_bucket.a"}}, got); diff != "" {
		t.Errorf("references (-want +got):\n%s", diff)
	}
}

// The resources of a module record at most 2^17 reference entries: past that, references are
// incomplete, with one warning.
func TestAttributeReferencesAreCapped(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("locals {\n  big = [")
	for i := range 1000 {
		fmt.Fprintf(&b, "aws_x.r%d.id, ", i)
	}
	b.WriteString("]\n}\nresource \"aws_s3_bucket\" \"b\" {\n")
	for i := range 140 {
		fmt.Fprintf(&b, "  a%d = local.big\n", i)
	}
	b.WriteString("}\n")
	instances := mustEvaluateTree(t, files(t, map[string]string{"main.tf": b.String()}))
	r, refs := resourceRefs(t, instances, "aws_s3_bucket.b")
	if !r.ReferencesIncomplete || len(refs) == 0 || len(refs) >= 140 {
		t.Errorf("incomplete %v with %d attributes recorded; want some, then incomplete", r.ReferencesIncomplete, len(refs))
	}
	warnings := 0
	for _, d := range instances[0].Module.Diagnostics {
		if d.Code == terraform.DiagReferencesIncomplete {
			warnings++
		}
	}
	if warnings != 1 {
		t.Errorf("%d references_incomplete warnings, want 1", warnings)
	}
}

// JSON bodies record references like HCL ones; a dynamic block iterator's references are not
// carried, so they mark the resource incomplete.
func TestReferencesInJSONAndDynamicBlocks(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf.json": `{"resource": {"aws_s3_bucket": {"j": {"bucket": "${aws_s3_bucket.logs.id}"}}}}`,
		"main.tf": `resource "aws_s3_bucket" "logs" {}
resource "aws_s3_bucket" "d" {
  dynamic "rule" {
    for_each = aws_s3_bucket.logs.tags
    content {
      v = rule.value
    }
  }
}
`,
	})
	instances := mustEvaluateTree(t, dir)
	j, refs := resourceRefs(t, instances, "aws_s3_bucket.j")
	if diff := cmp.Diff(map[string][]string{"bucket": {"aws_s3_bucket.logs"}}, refs); diff != "" || j.ReferencesIncomplete {
		t.Errorf("JSON references (-want +got):\n%s, incomplete %v", diff, j.ReferencesIncomplete)
	}
	if d, _ := resourceRefs(t, instances, "aws_s3_bucket.d"); !d.ReferencesIncomplete {
		t.Error("an iterator's references are carried silently, want incomplete")
	}
}

// manyRefs returns an HCL list of n distinct resource references.
func manyRefs(n int) string {
	var b strings.Builder
	b.WriteString("[")
	for i := range n {
		fmt.Fprintf(&b, "aws_x.r%d.id, ", i)
	}
	b.WriteString("]")
	return b.String()
}

// T-0108a review: a variable carries its module input's references. Locals and resources using
// it copy them only within the module's budget (2^17 entries), so 500 locals, or 2,000 count
// instances of 20 attributes, using a 20,000-reference input cannot hold millions of entries.
func TestInputReferencesStayWithinTheBudget(t *testing.T) {
	t.Parallel()
	var locals, resources strings.Builder
	locals.WriteString("variable \"x\" {}\nlocals {\n")
	for i := range 500 {
		fmt.Fprintf(&locals, "  l%d = var.x\n", i)
	}
	locals.WriteString("}\n")
	resources.WriteString("variable \"x\" {}\nresource \"aws_s3_bucket\" \"b\" {\n  count = 2000\n")
	for i := range 20 {
		fmt.Fprintf(&resources, "  a%d = var.x\n", i)
	}
	resources.WriteString("}\n")
	for name, child := range map[string]string{"locals": locals.String(), "resources": resources.String()} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := files(t, map[string]string{
				"main.tf":   "module \"c\" {\n  source = \"./c\"\n  x      = " + manyRefs(20_000) + "\n}\n",
				"c/main.tf": child,
			})
			c := instance(t, mustEvaluateTree(t, dir), "module.c")
			entries, incomplete := 0, 0
			for _, l := range c.Locals {
				entries += len(l.References)
				if l.ReferencesIncomplete {
					incomplete++
				}
			}
			for _, r := range c.Resources {
				for _, refs := range r.References {
					entries += len(refs)
				}
				if r.ReferencesIncomplete {
					incomplete++
				}
			}
			// The locals shape also uses up the tree's reference budget, so that instance is then
			// truncated (ADR 0010): the bound holds either way.
			if entries == 0 || entries > 1<<17 || incomplete == 0 {
				t.Errorf("%d reference entries, %d incomplete; want some entries, at most 2^17, and some incomplete",
					entries, incomplete)
			}
		})
	}
}

// An input whose references are incomplete (a local in a cycle, or a budget refusal) makes the
// child's uses incomplete too: never a silent "no references".
func TestIncompleteInputReferencesPropagate(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `locals {
  cyc = local.cyc2
  cyc2 = [local.cyc, aws_kms_key.k.arn]
}
module "c" {
  source = "./c"
  x      = local.cyc
}
`,
		"c/main.tf": "variable \"x\" {}\nlocals {\n  l = var.x\n}\nresource \"aws_s3_bucket\" \"b\" {\n  kms = var.x\n}\n",
	})
	instances := mustEvaluateTree(t, dir)
	b, _ := resourceRefs(t, instances, "module.c.aws_s3_bucket.b")
	c := instance(t, instances, "module.c")
	if !b.ReferencesIncomplete || !c.Locals["l"].ReferencesIncomplete || !c.Variables["x"].ReferencesIncomplete {
		t.Errorf("incomplete: resource %v, local %v, variable %v; want all true",
			b.ReferencesIncomplete, c.Locals["l"].ReferencesIncomplete, c.Variables["x"].ReferencesIncomplete)
	}
}

// The budget at, and one entry past, 2^17: 128 attributes of a 1,024-reference local fill it
// exactly; one more reference makes the resource incomplete, with one warning.
func TestReferenceBudgetBoundary(t *testing.T) {
	t.Parallel()
	for extra, over := range map[string]bool{"": false, "  extra = aws_y.z.id\n": true} {
		t.Run(fmt.Sprint(over), func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			b.WriteString("locals {\n  big = " + manyRefs(1024) + "\n}\nresource \"aws_s3_bucket\" \"b\" {\n")
			for i := range 128 {
				fmt.Fprintf(&b, "  a%d = local.big\n", i)
			}
			b.WriteString(extra + "}\n")
			instances := mustEvaluateTree(t, files(t, map[string]string{"main.tf": b.String()}))
			r, _ := resourceRefs(t, instances, "aws_s3_bucket.b")
			warned := 0
			for _, d := range instances[0].Module.Diagnostics {
				if d.Code == terraform.DiagReferencesIncomplete {
					warned++
				}
			}
			if r.ReferencesIncomplete != over || warned != map[bool]int{false: 0, true: 1}[over] {
				t.Errorf("incomplete %v with %d warnings; want %v", r.ReferencesIncomplete, warned, over)
			}
		})
	}
}

// A dynamic block whose for_each refers to something, or that is invalid, leaves the resource's
// references incomplete; one over a literal does not.
func TestDynamicBlocksAndReferences(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "lit" {
  dynamic "rule" {
    for_each = ["a"]
    content {
      v = "x"
    }
  }
}
resource "aws_s3_bucket" "ref" {
  dynamic "rule" {
    for_each = aws_x.y.list
    content {
      v = "x"
    }
  }
}
resource "aws_s3_bucket" "bad" {
  dynamic "rule" {
    content {
      v = aws_kms_key.k.arn
    }
  }
}
`,
	})
	instances := mustEvaluateTree(t, dir)
	for addr, want := range map[string]bool{"aws_s3_bucket.lit": false, "aws_s3_bucket.ref": true, "aws_s3_bucket.bad": true} {
		if r, _ := resourceRefs(t, instances, addr); r.ReferencesIncomplete != want {
			t.Errorf("%s incomplete = %v, want %v", addr, r.ReferencesIncomplete, want)
		}
	}
}
