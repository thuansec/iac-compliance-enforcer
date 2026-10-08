package terraform_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

func TestExpandDynamicBlocks(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"main.tf": `resource "aws_security_group" "sg" {
  count = 1

  ingress {
    from_port = 22
  }

  dynamic "ingress" {
    for_each = [80, 443]
    content {
      from_port = ingress.value
      idx       = ingress.key
      sg        = count.index
    }
  }

  ingress {
    from_port = 8080
  }

  dynamic "egress" {
    for_each = { a = 1 }
    iterator = e
    labels   = ["ignored"]
    content {
      k = e.key
      v = e.value
    }
  }

  dynamic "tag" {
    for_each = toset(["x"])
    content {
      k = tag.key
      v = tag.value
    }
  }

  dynamic "outer" {
    for_each = [[1, 2]]
    content {
      dynamic "inner" {
        for_each = outer.value
        content {
          v = inner.value
          o = outer.key
        }
      }
    }
  }

  dynamic "none" {
    for_each = []
    content {
      a = 1
    }
  }
}
`,
	})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", m.Diagnostics)
	}
	sg := resource(t, res, "aws_security_group.sg[0]")
	if len(sg.Unknown) != 0 {
		t.Errorf("unknown: %v", paths(sg.Unknown))
	}
	// Static and dynamic blocks of one type merge in source order.
	for path, want := range map[string]cty.Value{
		"ingress.0.from_port": cty.NumberIntVal(22),
		"ingress.1.from_port": cty.NumberIntVal(80),
		"ingress.1.idx":       cty.NumberIntVal(0),
		"ingress.2.from_port": cty.NumberIntVal(443),
		"ingress.2.idx":       cty.NumberIntVal(1),
		"ingress.2.sg":        cty.NumberIntVal(0),
		"ingress.3.from_port": cty.NumberIntVal(8080),
		"egress.0.k":          cty.StringVal("a"),
		"egress.0.v":          cty.NumberIntVal(1),
		"tag.0.k":             cty.StringVal("x"),
		"tag.0.v":             cty.StringVal("x"),
		"outer.0.inner.1.v":   cty.NumberIntVal(2),
		"outer.0.inner.1.o":   cty.NumberIntVal(0),
	} {
		if got := attr(t, sg.Value, path); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", path, got, want)
		}
	}
	if n := attr(t, sg.Value, "ingress").LengthInt(); n != 4 {
		t.Errorf("ingress has %d entries, want 4", n)
	}
	// No entries leave the type absent, as no static block would.
	if sg.Value.Type().HasAttribute("none") {
		t.Errorf("none = %#v, want absent", sg.Value.GetAttr("none"))
	}
	// Attribute ranges point at the content attributes.
	if r := sg.Attributes["ingress.2.from_port"]; r.Start.Line != 11 {
		t.Errorf("ingress.2.from_port range %v, want line 11", r)
	}
	if r := sg.Attributes["outer.0.inner.1.v"]; r.Start.Line != 45 {
		t.Errorf("outer.0.inner.1.v range %v, want line 45", r)
	}
}

// TestExpandDynamicBlocksFailClosed: an unknown for_each is one entry evaluated with an
// unknown iterator, and the block type's path is unknown; an invalid dynamic block makes its
// type unknown. Both warn.
func TestExpandDynamicBlocksFailClosed(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"main.tf": `variable "ports" {}

variable "secret_ports" {
  default   = [5432]
  sensitive = true
}

resource "x" "u" {
  dynamic "ingress" {
    for_each = var.ports
    content {
      from_port = ingress.value
      proto     = "tcp"
    }
  }

  dynamic "s" {
    for_each = toset([aws_x.y.id])
    content {
      a = 1
    }
  }

  dynamic "secret" {
    for_each = var.secret_ports
    content {
      port = secret.value
    }
  }
}

resource "x" "bad" {
  dynamic "str" {
    for_each = "abc"
    content {}
  }
  dynamic "nul" {
    for_each = null
    content {}
  }
  dynamic "nocontent" {
    for_each = [1]
  }
  dynamic "twocontent" {
    for_each = [1]
    content {}
    content {}
  }
  dynamic "noforeach" {
    content {}
  }
  dynamic "iter" {
    for_each = [1]
    iterator = "x"
    content {}
  }
  dynamic {
    for_each = [1]
    content {}
  }
  dynamic "a" "b" {
    for_each = [1]
    content {}
  }
  dynamic "err" {
    for_each = upper(1, 2)
    content {}
  }
  ok = 1
}
`,
	})
	u := resource(t, res, "x.u")
	if diff := cmp.Diff([]string{"ingress", "s"}, paths(u.Unknown)); diff != "" {
		t.Errorf("x.u unknown (-want +got):\n%s", diff)
	}
	if got := attr(t, u.Value, "ingress.0.proto"); !got.RawEquals(cty.StringVal("tcp")) {
		t.Errorf("ingress.0.proto = %#v, want the static attribute of the one entry", got)
	}
	if got := attr(t, u.Value, "secret.0"); !got.HasMark(terraform.SensitiveMark) {
		t.Errorf("secret.0 = %#v, want sensitive", got)
	}
	bad := resource(t, res, "x.bad")
	if diff := cmp.Diff([]string{"err", "iter", "nocontent", "noforeach", "nul", "str", "twocontent"}, paths(bad.Unknown)); diff != "" {
		t.Errorf("x.bad unknown (-want +got):\n%s", diff)
	}
	if got := attr(t, bad.Value, "ok"); !got.RawEquals(cty.NumberIntVal(1)) {
		t.Errorf("ok = %#v", got)
	}
	want := []string{
		"unknown_expansion@main.tf:10", "unknown_expansion@main.tf:18",
		"invalid_expansion@main.tf:34", "invalid_expansion@main.tf:38", "invalid_expansion@main.tf:41",
		"invalid_expansion@main.tf:44", "invalid_expansion@main.tf:49", "invalid_expansion@main.tf:54",
		"invalid_expansion@main.tf:57", "invalid_expansion@main.tf:61", "evaluation@main.tf:66",
	}
	if diff := cmp.Diff(want, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
	for _, d := range m.Diagnostics {
		if strings.Contains(d.Summary+d.Detail, "5432") {
			t.Errorf("diagnostic quotes a value: %v", d)
		}
	}
}

// TestDynamicBlockLimit: a dynamic block keeps its first 10,000 entries, marks its type
// unknown (entries are missing) and warns.
func TestDynamicBlockLimit(t *testing.T) {
	t.Parallel()
	src := `resource "x" "d" {
  dynamic "e" {
    for_each = flatten([for i in range(100) : [for j in range(101) : j]])
    content {
      v = e.value
    }
  }
}
`
	m, res := decodeResources(t, map[string]string{"main.tf": src})
	d := res[0]
	if n := attr(t, d.Value, "e").LengthInt(); n != 10000 {
		t.Errorf("e has %d entries, want 10,000", n)
	}
	if diff := cmp.Diff([]string{"e"}, paths(d.Unknown)); diff != "" {
		t.Errorf("unknown (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"expansion_limit@main.tf:3"}, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
}

// TestDynamicBlocksShareModuleLimits: entries count toward the module's re-evaluation work, so
// many instances of many entries stop at the module limit.
func TestDynamicBlocksShareModuleLimits(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := range 3 {
		fmt.Fprintf(&b, `resource "x" "r%d" {
  count = 100
  dynamic "e" {
    for_each = range(1000)
    content {
      v = "%s${e.value}"
    }
  }
}
`, i, strings.Repeat("x", 40))
	}
	m, res := decodeResources(t, map[string]string{"main.tf": b.String()})
	limited := 0
	for _, r := range res {
		if len(r.Unknown) > 0 {
			limited++
		}
	}
	if limited == 0 || !strings.Contains(strings.Join(codes(m), " "), "expansion_limit@") {
		t.Errorf("%d instances with unknown entries, diagnostics %v; want the module limit reached", limited, codes(m))
	}
}

// TestDynamicIteratorScope: a nested dynamic block may shadow an outer iterator; the outer one
// is back for the blocks after it.
func TestDynamicIteratorScope(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"main.tf": `resource "x" "s" {
  dynamic "a" {
    for_each = [1]
    content {
      dynamic "b" {
        for_each = [2]
        iterator = a
        content {
          v = a.value
        }
      }
      dynamic "c" {
        for_each = [a.value]
        content {
          w = c.value
        }
      }
    }
  }
}
`,
	})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", m.Diagnostics)
	}
	for path, want := range map[string]cty.Value{"a.0.b.0.v": cty.NumberIntVal(2), "a.0.c.0.w": cty.NumberIntVal(1)} {
		if got := attr(t, res[0].Value, path); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", path, got, want)
		}
	}
}

// TestDynamicBlocksShareStructureLimit: entries with many nested blocks are cheap to evaluate
// but large to hold, so the module's structure estimate stops them first (after about 5,500
// entries, at the sixth instance), long before the re-evaluation work would (about 14,000).
func TestDynamicBlocksShareStructureLimit(t *testing.T) {
	t.Parallel()
	src := "resource \"x\" \"r\" {\n  count = 20\n  dynamic \"e\" {\n    for_each = range(1000)\n    content {\n" +
		strings.Repeat("      x {}\n", 30) + "    }\n  }\n}\n"
	m, res := decodeResources(t, map[string]string{"main.tf": src})
	first := -1
	for i, r := range res {
		if len(r.Unknown) > 0 {
			first = i
			break
		}
	}
	if first < 0 || first > 6 || !strings.Contains(strings.Join(codes(m), " "), "expansion_limit@main.tf:4") {
		t.Errorf("first instance with unknown entries %d, diagnostics %v; want the structure limit by instance 6", first, codes(m))
	}
}

// TestDynamicIteratorShadowsRoots: an iterator named local, var or path shadows that root in
// its content, as in Terraform; otherwise iace would check a value Terraform does not apply.
func TestDynamicIteratorShadowsRoots(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"main.tf": `variable "value" {
  default = "from-var"
}

locals {
  value = "AES256"
}

resource "x" "s" {
  dynamic "l" {
    for_each = ["none"]
    iterator = local
    content {
      alg = local.value
    }
  }
  dynamic "v" {
    for_each = ["iter"]
    iterator = var
    content {
      val = var.value
    }
  }
  dynamic "p" {
    for_each = { module = "m" }
    iterator = path
    content {
      k = path.key
    }
  }
  after = local.value
}
`,
	})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", m.Diagnostics)
	}
	for path, want := range map[string]cty.Value{
		"l.0.alg": cty.StringVal("none"),
		"v.0.val": cty.StringVal("iter"),
		"p.0.k":   cty.StringVal("module"),
		"after":   cty.StringVal("AES256"),
	} {
		if got := attr(t, res[0].Value, path); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", path, got, want)
		}
	}
}

// TestDynamicBlockAtLimit: exactly 10,000 entries are all kept, with no warning.
func TestDynamicBlockAtLimit(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{"main.tf": `resource "x" "d" {
  dynamic "e" {
    for_each = flatten([for i in range(100) : [for j in range(100) : j]])
    content {
      v = e.value
    }
  }
}
`})
	if n := attr(t, res[0].Value, "e").LengthInt(); n != 10000 || len(res[0].Unknown) != 0 || len(m.Diagnostics) != 0 {
		t.Errorf("%d entries, unknown %v, diagnostics %v; want 10,000 and none", n, paths(res[0].Unknown), codes(m))
	}
}

// TestDynamicBlockInvalidForms: forms hcl rejects make the type unknown with a warning.
func TestDynamicBlockInvalidForms(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{"main.tf": `resource "x" "bad" {
  dynamic "lifecycle" {
    for_each = [1]
    content {}
  }
  dynamic "extra" {
    for_each = [1]
    other    = 1
    content {}
  }
  dynamic "block" {
    for_each = [1]
    content {}
    nested {}
  }
  dynamic "labeled" {
    for_each = [1]
    content "x" {}
  }
}
`})
	if diff := cmp.Diff([]string{"block", "extra", "labeled", "lifecycle"}, paths(res[0].Unknown)); diff != "" {
		t.Errorf("unknown (-want +got):\n%s", diff)
	}
	want := []string{"invalid_expansion@main.tf:2", "invalid_expansion@main.tf:8", "invalid_expansion@main.tf:14", "invalid_expansion@main.tf:18"}
	if diff := cmp.Diff(want, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
}
