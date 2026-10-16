package terraform_test

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// A resource attribute set through sensitive() keeps the mark at its path, which the input
// document lists as sensitive, and nonsensitive() removes it, as in Terraform (T-0126).
func TestSensitiveFunctionsInResources(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{"main.tf": `variable "p" {
  default = "fake-password"
}
variable "s" {
  default   = "fake-token"
  sensitive = true
}
resource "x_db" "a" {
  password = sensitive(var.p)
  token    = nonsensitive(var.s)
  nested   = { inner = sensitive("fake") }
  plain    = var.p
  big      = [for i in range(1000) : [for j in range(20) : sensitive(var.p)]]
}
`})
	a := resource(t, res, "x_db.a")
	for name, want := range map[string]cty.Value{
		"password": cty.StringVal("fake-password").Mark(terraform.SensitiveMark),
		"token":    cty.StringVal("fake-token"),
		"plain":    cty.StringVal("fake-password"),
	} {
		if got := attr(t, a.Value, name); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", name, got, want)
		}
	}
	if inner := attr(t, a.Value, "nested.inner"); !inner.HasMark(terraform.SensitiveMark) {
		t.Errorf("nested.inner = %#v, want sensitive", inner)
	}
	// Refused as too large, it is a marked unknown though its inputs are plain.
	if big := a.Value.GetAttr("big"); big.IsKnown() || !big.HasMark(terraform.SensitiveMark) {
		t.Errorf("big = %#v, want unknown and sensitive", big)
	}
	if got := codes(m); len(got) != 1 || got[0] != "value_too_large@main.tf:13" {
		t.Errorf("diagnostics %v; want big refused as too large", got)
	}
}

// A module output set through sensitive() reaches its callers marked (T-0126). The secret
// output also sets `sensitive = true`, which marks it anyway; nested has only sensitive().
func TestSensitiveFunctionsInModuleOutputs(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `module "c" {
  source = "./c"
}
resource "x" "a" {
  secret = module.c.secret
  plain  = module.c.plain
  nested = module.c.nested
}
`,
		"c/main.tf": `output "secret" {
  value     = sensitive("fake-secret")
  sensitive = true
}
output "plain" {
  value = nonsensitive(sensitive("visible"))
}
output "nested" {
  value = { a = sensitive("fake-nested") }
}
`,
	})
	root := instance(t, mustEvaluateTree(t, dir), "")
	if got, want := resourceAttr(t, root, "secret"), cty.StringVal("fake-secret").Mark(terraform.SensitiveMark); !got.RawEquals(want) {
		t.Errorf("secret = %#v, want %#v", got, want)
	}
	if got, want := resourceAttr(t, root, "plain"), cty.StringVal("visible"); !got.RawEquals(want) {
		t.Errorf("plain = %#v, want %#v", got, want)
	}
	// Without `sensitive = true`, the output's mark comes from sensitive() alone.
	if a := resourceAttr(t, root, "nested").GetAttr("a"); !a.HasMark(terraform.SensitiveMark) {
		t.Errorf("nested.a = %#v, want sensitive", a)
	}
}
