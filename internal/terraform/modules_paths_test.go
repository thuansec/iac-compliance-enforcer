package terraform_test

import (
	"context"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// pathOutputs is a module whose outputs expose path.* and the file functions.
const pathOutputs = `output "module" {
  value = path.module
}
output "root" {
  value = path.root
}
output "own" {
  value = file("${path.module}/policy.json")
}
output "own_exists" {
  value = fileexists("${path.module}/policy.json")
}
output "bare_exists" {
  value = fileexists("policy.json")
}
output "from_root" {
  value = file("root.txt")
}
output "tpl" {
  value = templatefile("${path.module}/t.tftpl", { n = "x" })
}
`

// Inside a child instance, path.module is the child's path from the root module, path.root is
// ".", and the file functions resolve relative paths against the root module's directory, as
// Terraform does.
func TestChildModulePathsResolveFromTheRoot(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"envs/prod/main.tf":           module("net", "../../modules/net") + pathOutputs,
		"envs/prod/root.txt":          "root file",
		"envs/prod/policy.json":       "root policy",
		"envs/prod/t.tftpl":           "root ${n}",
		"modules/net/main.tf":         module("sub", "./sub") + pathOutputs,
		"modules/net/policy.json":     "net policy",
		"modules/net/t.tftpl":         "net ${n}",
		"modules/net/sub/main.tf":     pathOutputs,
		"modules/net/sub/policy.json": "sub policy",
		"modules/net/sub/t.tftpl":     "sub ${n}",
	})
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	limits := terraform.DefaultLimits()
	d, err := terraform.Discover(context.Background(), r, limits)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := terraform.LoadModuleTree(context.Background(), r, d, "envs/prod", limits, terraform.TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	instances, err := terraform.EvaluateTree(context.Background(), r, tree, terraform.VarOptions{}, limits)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]cty.Value{
		"": {
			"module": cty.StringVal("."), "root": cty.StringVal("."),
			"own": cty.StringVal("root policy"), "own_exists": cty.True, "bare_exists": cty.True,
			"from_root": cty.StringVal("root file"), "tpl": cty.StringVal("root x"),
		},
		"module.net": {
			"module": cty.StringVal("../../modules/net"), "root": cty.StringVal("."),
			"own": cty.StringVal("net policy"), "own_exists": cty.True,
			// A bare relative path resolves against the root module, not the child.
			"bare_exists": cty.True,
			"from_root":   cty.StringVal("root file"), "tpl": cty.StringVal("net x"),
		},
		"module.net.module.sub": {
			"module": cty.StringVal("../../modules/net/sub"), "root": cty.StringVal("."),
			"own": cty.StringVal("sub policy"), "own_exists": cty.True, "bare_exists": cty.True,
			"from_root": cty.StringVal("root file"), "tpl": cty.StringVal("sub x"),
		},
	}
	for _, inst := range instances {
		w, ok := want[inst.Address]
		if !ok {
			t.Fatalf("unexpected instance %q", inst.Address)
		}
		for name, v := range w {
			if got := inst.Outputs[name].Value; !got.RawEquals(v) {
				t.Errorf("%s output %s = %#v, want %#v", inst.Address, name, got, v)
			}
		}
		if len(inst.Module.Diagnostics) != 0 {
			t.Errorf("%s diagnostics: %v", inst.Address, diagLines(inst.Module))
		}
	}
}

// A child can read anywhere in the scan root through path.module, but never outside it.
func TestChildModuleFilesStayInTheScanRoot(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":   module("c", "./c"),
		"c/main.tf": "output \"o\" {\n  value = file(\"${path.module}/../../outside.txt\")\n}\n",
	})
	instances := mustEvaluateTree(t, dir)
	c := instance(t, instances, "module.c")
	if c.Outputs["o"].Value.IsKnown() {
		t.Error("a file outside the scan root was read")
	}
	if got := diagCodesAt(c.Module, 2); len(got) != 1 || got[0] != terraform.DiagFileOutsideModule {
		t.Errorf("diagnostics %v, want file_outside_module", got)
	}
}

// A module resolved through the module manifest has path.module under .terraform, and a child's
// template error names the template by its scan-root path.
func TestRemoteModulePathAndTemplateDiagnostics(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": module("r", "acme/r/aws") + module("net", "./modules/net"),
		".terraform/modules/r/main.tf": "output \"module\" {\n  value = path.module\n}\n" +
			"output \"own\" {\n  value = file(\"${path.module}/data.txt\")\n}\n",
		".terraform/modules/r/data.txt":   "remote data",
		".terraform/modules/modules.json": `{"Modules":[{"Key":"r","Source":"registry.terraform.io/acme/r/aws","Dir":".terraform/modules/r"}]}`,
		"modules/net/main.tf":             "output \"t\" {\n  value = templatefile(\"${path.module}/bad.tftpl\", {})\n}\n",
		"modules/net/bad.tftpl":           "${",
	})
	tree := loadTrusted(t, dir, ".")
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	instances, err := terraform.EvaluateTree(context.Background(), r, tree, terraform.VarOptions{}, terraform.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	remote := instance(t, instances, "module.r")
	if got := remote.Outputs["module"].Value; !got.RawEquals(cty.StringVal(".terraform/modules/r")) {
		t.Errorf("remote path.module = %#v", got)
	}
	if got := remote.Outputs["own"].Value; !got.RawEquals(cty.StringVal("remote data")) {
		t.Errorf("remote file = %#v", got)
	}
	net := instance(t, instances, "module.net")
	found := false
	for _, d := range net.Module.Diagnostics {
		if d.Code == terraform.DiagTemplateError {
			found = d.File == "modules/net/bad.tftpl"
			if !found {
				t.Errorf("template error at %q, want modules/net/bad.tftpl", d.File)
			}
		}
	}
	if !found {
		t.Errorf("no template_error: %v", diagLines(net.Module))
	}
}
