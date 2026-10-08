package terraform_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

func addresses(res []terraform.Resource) []string {
	out := []string{}
	for _, r := range res {
		out = append(out, r.Address)
	}
	return out
}

func TestExpandCountAndForEach(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"main.tf": `variable "pw" {
  default   = "hunter2"
  sensitive = true
}

variable "sn" {
  default   = 2
  sensitive = true
}

resource "x" "c" {
  count  = 2
  bucket = "logs-${count.index}"
  static = "s"
}

resource "x" "m" {
  for_each = { b = "B", a = "A" }
  key      = each.key
  value    = each.value
}

resource "x" "s" {
  for_each = toset(["z", "y"])
  value    = each.value
}

resource "x" "o" {
  for_each = { web = { port = 80 } }
  port     = each.value.port
}

resource "x" "str" {
  count = "1"
}

resource "x" "q" {
  for_each = { "a\"b" = 1, "t$${x}" = 1, "p%%{y}" = 1, "c\u0007" = 1 }
}

resource "x" "scount" {
  count = var.sn
  index = count.index
}

resource "x" "sens" {
  for_each = { a = var.pw }
  secret   = each.value
}

resource "x" "partly" {
  for_each = { a = aws_x.y.id }
  value    = each.value
}

data "x" "d" {
  count = 1
}

resource "x" "zero" {
  count = 0
}

resource "x" "empty" {
  for_each = {}
}

resource "x" "emptyset" {
  for_each = toset([])
}
`,
	})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", m.Diagnostics)
	}
	want := []string{
		"x.c[0]", "x.c[1]", `x.m["a"]`, `x.m["b"]`, `x.s["y"]`, `x.s["z"]`, `x.o["web"]`,
		"x.str[0]", `x.q["a\"b"]`, `x.q["c\u0007"]`, `x.q["p%%{y}"]`, `x.q["t$${x}"]`,
		"x.scount[0]", "x.scount[1]", `x.sens["a"]`, `x.partly["a"]`, "data.x.d[0]",
	}
	if diff := cmp.Diff(want, addresses(res)); diff != "" {
		t.Fatalf("addresses (-want +got):\n%s", diff)
	}

	c1 := resource(t, res, "x.c[1]")
	if c1.BaseAddress != "x.c" || c1.Index != model.IntKey(1) || c1.CountUnknown || c1.ForEachUnknown {
		t.Errorf("x.c[1] = base %q, index %v, unknown %v/%v", c1.BaseAddress, c1.Index, c1.CountUnknown, c1.ForEachUnknown)
	}
	if got := attr(t, c1.Value, "bucket"); !got.RawEquals(cty.StringVal("logs-1")) {
		t.Errorf("x.c[1].bucket = %#v", got)
	}
	mb := resource(t, res, `x.m["b"]`)
	if mb.BaseAddress != "x.m" || mb.Index != model.StringKey("b") {
		t.Errorf(`x.m["b"] = base %q, index %v`, mb.BaseAddress, mb.Index)
	}
	for path, want := range map[string]cty.Value{"key": cty.StringVal("b"), "value": cty.StringVal("B")} {
		if got := attr(t, mb.Value, path); !got.RawEquals(want) {
			t.Errorf(`x.m["b"].%s = %#v`, path, got)
		}
	}
	// A sensitive count expands; its indexes are not sensitive.
	if got := attr(t, resource(t, res, "x.scount[1]").Value, "index"); !got.RawEquals(cty.NumberIntVal(1)) {
		t.Errorf("x.scount[1].index = %#v", got)
	}
	if got := attr(t, resource(t, res, `x.s["z"]`).Value, "value"); !got.RawEquals(cty.StringVal("z")) {
		t.Errorf(`x.s["z"].value = %#v`, got)
	}
	if got := attr(t, resource(t, res, `x.o["web"]`).Value, "port"); !got.RawEquals(cty.NumberIntVal(80)) {
		t.Errorf(`x.o["web"].port = %#v`, got)
	}
	if got := attr(t, resource(t, res, `x.sens["a"]`).Value, "secret"); !got.HasMark(terraform.SensitiveMark) {
		t.Errorf(`x.sens["a"].secret = %#v, want sensitive`, got)
	}
	if diff := cmp.Diff([]string{"value"}, paths(resource(t, res, `x.partly["a"]`).Unknown)); diff != "" {
		t.Errorf("x.partly unknown (-want +got):\n%s", diff)
	}
	if d := resource(t, res, "data.x.d[0]"); d.BaseAddress != "data.x.d" || d.Mode != model.ModeData {
		t.Errorf("data.x.d[0] = %+v", d)
	}
	// Without count or for_each, the address has no key.
	_, plain := decodeResources(t, map[string]string{"main.tf": "resource \"x\" \"p\" {}\n"})
	if p := plain[0]; p.Address != "x.p" || p.BaseAddress != "x.p" || !p.Index.IsNone() {
		t.Errorf("x.p = %+v", p)
	}
}

// TestExpandUnknownAndInvalid: an expansion iace cannot know, or that Terraform would reject,
// is one placeholder instance whose values are evaluated with an unknown count.index or each.
func TestExpandUnknownAndInvalid(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"main.tf": `variable "n" {}

variable "pw" {
  default   = 2
  sensitive = true
}

resource "x" "uc" {
  count  = var.n
  bucket = "logs-${count.index}"
  static = "s"
}

resource "x" "uf" {
  for_each = aws_x.y.tags
  key      = each.key
}

resource "x" "us" {
  for_each = toset([aws_x.y.id])
}

resource "x" "neg" {
  count = -1
}

resource "x" "frac" {
  count = 1.5
}

resource "x" "null" {
  count = null
}

resource "x" "word" {
  count = "two"
}

resource "x" "list" {
  for_each = ["a"]
}

resource "x" "nums" {
  for_each = toset([1, 2])
}

resource "x" "sfe" {
  for_each = toset([tostring(var.pw)])
}

resource "x" "both" {
  count    = 1
  for_each = {}
}

resource "x" "fnull" {
  for_each = null
}

resource "x" "err" {
  count = upper(1, 2)
}
`,
	})
	want := []string{
		"x.uc[*]", "x.uf[*]", "x.us[*]", "x.neg[*]", "x.frac[*]", "x.null[*]", "x.word[*]",
		"x.list[*]", "x.nums[*]", "x.sfe[*]", "x.both[*]", "x.fnull[*]", "x.err[*]",
	}
	if diff := cmp.Diff(want, addresses(res)); diff != "" {
		t.Fatalf("addresses (-want +got):\n%s", diff)
	}
	for _, r := range res {
		if !r.Index.IsNone() || r.BaseAddress+"[*]" != r.Address {
			t.Errorf("%s: index %v, base %q", r.Address, r.Index, r.BaseAddress)
		}
		usesCount := strings.Contains(r.Address, "count") || r.Address == "x.uc[*]" || r.Address == "x.neg[*]" ||
			r.Address == "x.frac[*]" || r.Address == "x.null[*]" || r.Address == "x.word[*]" || r.Address == "x.err[*]"
		if r.Address == "x.both[*]" {
			if !r.CountUnknown || !r.ForEachUnknown {
				t.Errorf("x.both: count/for_each unknown %v/%v, want both", r.CountUnknown, r.ForEachUnknown)
			}
			continue
		}
		if r.CountUnknown != usesCount || r.ForEachUnknown == usesCount {
			t.Errorf("%s: count unknown %v, for_each unknown %v", r.Address, r.CountUnknown, r.ForEachUnknown)
		}
	}
	uc := resource(t, res, "x.uc[*]")
	if diff := cmp.Diff([]string{"bucket"}, paths(uc.Unknown)); diff != "" {
		t.Errorf("x.uc unknown (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"key"}, paths(resource(t, res, "x.uf[*]").Unknown)); diff != "" {
		t.Errorf("x.uf unknown (-want +got):\n%s", diff)
	}
	wantDiags := []string{
		"unknown_expansion@main.tf:9", "unknown_expansion@main.tf:15", "unknown_expansion@main.tf:20",
		"invalid_expansion@main.tf:24", "invalid_expansion@main.tf:28", "invalid_expansion@main.tf:32",
		"invalid_expansion@main.tf:36", "invalid_expansion@main.tf:40", "invalid_expansion@main.tf:44",
		"invalid_expansion@main.tf:48", "invalid_expansion@main.tf:52",
		"invalid_expansion@main.tf:57", "evaluation@main.tf:61",
	}
	if diff := cmp.Diff(wantDiags, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
	for _, d := range m.Diagnostics {
		if strings.Contains(d.Summary+d.Detail, "hunter2") || d.Severity != terraform.SeverityWarning {
			t.Errorf("diagnostic %v", d)
		}
	}
}

// TestExpansionLimits: a resource keeps its first 10,000 instances, and a module 100,000.
func TestExpansionLimits(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("resource \"x\" \"big\" {\n  count = 10001\n}\n\n")
	// range stops at 1,024, so the 10,100 keys come from two nested fors.
	b.WriteString("resource \"x\" \"keys\" {\n  for_each = { for p in flatten([for i in range(100) : [for j in range(101) : \"${i}-${j}\"]]) : p => 1 }\n}\n\n")
	for i := range 9 {
		fmt.Fprintf(&b, "resource \"x\" \"r%d\" {\n  count = 10000\n}\n\n", i)
	}
	m, res := decodeResources(t, map[string]string{"main.tf": b.String()})
	counts := map[string]int{}
	for _, r := range res {
		counts[r.BaseAddress]++
	}
	if counts["x.big"] != 10000 || counts["x.keys"] != 10000 {
		t.Errorf("x.big has %d instances and x.keys %d, want 10,000 each", counts["x.big"], counts["x.keys"])
	}
	if len(res) != 100_000 || counts["x.r7"] != 10000 || counts["x.r8"] != 0 {
		t.Errorf("%d instances (x.r7 %d, x.r8 %d), want the module limit of 100,000", len(res), counts["x.r7"], counts["x.r8"])
	}
	if res[9999].Address != "x.big[9999]" {
		t.Errorf("last kept instance %s, want x.big[9999]", res[9999].Address)
	}
	want := []string{"expansion_limit@main.tf:2", "expansion_limit@main.tf:6", "expansion_limit@main.tf:42"}
	if diff := cmp.Diff(want, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
}

// TestExpansionWorkLimit: instances evaluate their block again, so a large block's instances
// stop at the module's expansion work, which bounds the time they take.
func TestExpansionWorkLimit(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("resource \"x\" \"big\" {\n  count = 10000\n")
	for i := range 200 {
		fmt.Fprintf(&b, "  a%03d = \"${count.index}-%s\"\n", i, strings.Repeat("v", 4))
	}
	b.WriteString("}\n\nresource \"x\" \"after\" {}\n")
	m, res := decodeResources(t, map[string]string{"main.tf": b.String()})
	// The attributes are about 6 KB, so 2^21 bytes allow about 350 instances after the first.
	n := len(res) - 1
	if n < 250 || n > 450 || res[len(res)-1].Address != "x.after" {
		t.Errorf("%d instances of x.big (last %s), want the expansion work limit", n, res[len(res)-1].Address)
	}
	if diff := cmp.Diff([]string{"expansion_limit@main.tf:2"}, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
}

// TestExpandKeepsEachSensitivity: an attribute that fails to evaluate from a sensitive
// each.value is unknown and still sensitive (fail closed).
func TestExpandKeepsEachSensitivity(t *testing.T) {
	t.Parallel()
	_, res := decodeResources(t, map[string]string{
		"main.tf": `variable "pw" {
  default   = "hunter2"
  sensitive = true
}

resource "x" "s" {
  for_each = { a = var.pw }
  bad      = upper(each.value, 1)
}
`,
	})
	if got := attr(t, resource(t, res, `x.s["a"]`).Value, "bad"); got.IsKnown() || !got.HasMark(terraform.SensitiveMark) {
		t.Errorf("bad = %#v, want unknown and sensitive", got)
	}
}
