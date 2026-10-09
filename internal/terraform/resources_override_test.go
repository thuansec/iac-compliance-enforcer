package terraform_test

import (
	"context"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// A weakening override (threat model T14) reaches the evaluated resources of a scan, in a root
// module and in a local child module, as Terraform would apply it.
func TestWeakeningOverrideReachesTheScan(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":                "resource \"aws_s3_bucket\" \"root\" {\n  acl = \"private\"\n}\nmodule \"child\" {\n  source = \"./child\"\n}\n",
		"main_override.tf":       "resource \"aws_s3_bucket\" \"root\" {\n  acl = \"public-read\"\n}\n",
		"child/main.tf":          "resource \"aws_s3_bucket\" \"child\" {\n  acl = \"private\"\n}\n",
		"child/main_override.tf": "resource \"aws_s3_bucket\" \"child\" {\n  acl = \"public-read\"\n}\n",
	})
	results, err := evaluateRoots(context.Background(), t, dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]cty.Value{}
	for _, res := range results {
		for _, inst := range res.Instances {
			for _, r := range inst.Resources {
				got[r.Address] = r.Value.GetAttr("acl")
			}
		}
	}
	for _, addr := range []string{"aws_s3_bucket.root", "module.child.aws_s3_bucket.child"} {
		if v, ok := got[addr]; !ok || !v.RawEquals(cty.StringVal("public-read")) {
			t.Errorf("%s acl = %#v, want the override's public-read (all: %v)", addr, v, got)
		}
	}
}

// A duplicate in a child module expanded by count is reported once, on the child's module.
func TestDuplicateResourceInExpandedChild(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":       "module \"c\" {\n  source = \"./child\"\n  count  = 2\n}\n",
		"child/main.tf": "resource \"aws_s3_bucket\" \"b\" {}\nresource \"aws_s3_bucket\" \"b\" {}\n",
	})
	results, err := evaluateRoots(context.Background(), t, dir)
	if err != nil {
		t.Fatal(err)
	}
	children := 0
	for _, res := range results {
		for _, inst := range res.Instances {
			if inst.Module.Dir != "child" {
				continue
			}
			children++
			n := 0
			for _, d := range inst.Module.Diagnostics {
				if d.Code == terraform.DiagDuplicateResource {
					n++
				}
			}
			if n != 1 || !inst.Module.HasErrors() {
				t.Errorf("%d duplicate_resource diagnostics on a child instance, want 1 and errors", n)
			}
		}
	}
	if children != 2 {
		t.Errorf("%d child instances, want 2", children)
	}
}
