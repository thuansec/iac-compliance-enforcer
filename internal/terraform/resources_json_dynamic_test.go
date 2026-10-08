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

func TestExpandJSONDynamicBlocks(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"locals.tf": "locals {\n  value = \"AES256\"\n}\n",
		"main.tf.json": `{
  "resource": {
    "aws_security_group": {
      "sg": {
        "ingress": [{"from_port": 22}],
        "dynamic": {
          "ingress": {
            "for_each": [80, 443],
            "content": {"from_port": "${ingress.value}", "idx": "${ingress.key}"}
          },
          "egress": [{
            "for_each": {"a": 1},
            "iterator": "e",
            "labels": ["ignored"],
            "content": {"k": "${e.key}", "v": "${e.value}"}
          }],
          "outer": {
            "for_each": [[1, 2]],
            "content": {
              "dynamic": {
                "inner": {"for_each": "${outer.value}", "content": {"v": "${inner.value}", "o": "${outer.key}"}}
              }
            }
          },
          "shadow": {
            "for_each": ["none"],
            "iterator": "local",
            "content": {"alg": "${local.value}"}
          }
        },
        "shadowed": {"dynamic": {"r": {"for_each": ["a"], "iterator": "local", "content": {"v": "${local.value}"}}}},
        "setting": {
          "name": "s",
          "dynamic": {"rule": {"for_each": [5], "content": {"port": "${rule.value}"}}}
        },
        "after": "${local.value}"
      }
    }
  }
}
`,
	})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", m.Diagnostics)
	}
	sg := res[0]
	if len(sg.Unknown) != 0 {
		t.Errorf("unknown: %v", paths(sg.Unknown))
	}
	for path, want := range map[string]cty.Value{
		"ingress.0.from_port":   cty.NumberIntVal(22),
		"ingress.1.from_port":   cty.NumberIntVal(80),
		"ingress.2.from_port":   cty.NumberIntVal(443),
		"ingress.2.idx":         cty.NumberIntVal(1),
		"egress.0.k":            cty.StringVal("a"),
		"egress.0.v":            cty.NumberIntVal(1),
		"outer.0.inner.1.v":     cty.NumberIntVal(2),
		"outer.0.inner.1.o":     cty.NumberIntVal(0),
		"shadow.0.alg":          cty.StringVal("none"),
		"setting.0.name":        cty.StringVal("s"),
		"setting.0.rule.0.port": cty.NumberIntVal(5),
		"shadowed.0.r.0.v":      cty.StringVal("a"),
		"after":                 cty.StringVal("AES256"),
	} {
		if got := attr(t, sg.Value, path); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", path, got, want)
		}
	}
	if n := attr(t, sg.Value, "ingress").LengthInt(); n != 3 {
		t.Errorf("ingress has %d entries, want 3", n)
	}
	// Content attribute ranges are recorded under the entry paths.
	if r := sg.Attributes["ingress.2.from_port"]; r.Filename != "main.tf.json" || r.Start.Line != 9 {
		t.Errorf("ingress.2.from_port range %v, want main.tf.json line 9", r)
	}
	if _, ok := sg.Attributes["setting.0.rule.0.port"]; !ok {
		t.Errorf("no range for setting.0.rule.0.port in %v", sg.Attributes)
	}
}

// TestJSONDynamicBlocksFailClosed mirrors the HCL cases: an unknown for_each is one entry and
// an unknown type path, a sensitive for_each marks the entries, invalid forms make the type
// unknown; each warns.
func TestJSONDynamicBlocksFailClosed(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"vars.tf": "variable \"ports\" {}\n\nvariable \"secret_ports\" {\n  default   = [5432]\n  sensitive = true\n}\n",
		"main.tf.json": `{
  "resource": {
    "x": {
      "u": {
        "dynamic": {
          "ingress": {"for_each": "${var.ports}", "content": {"from_port": "${ingress.value}", "proto": "tcp"}},
          "secret": {"for_each": "${var.secret_ports}", "content": {"port": "${secret.value}"}}
        }
      },
      "bad": {
        "ok": 1,
        "dynamic": {
          "noforeach": {"content": {}},
          "twocontent": {"for_each": [1], "content": [{}, {}]},
          "strcontent": {"for_each": [1], "content": "x"},
          "extra": {"for_each": [1], "other": 1, "content": {}},
          "iter": {"for_each": [1], "iterator": "a.b", "content": {}},
          "nul": {"for_each": null, "content": {}},
          "lifecycle": {"for_each": [1], "content": {}}
        },
        "mixed": [1, {"dynamic": {"z": {"for_each": [1], "content": {}}}}]
      }
    }
  }
}
`,
	})
	u := res[0]
	if diff := cmp.Diff([]string{"ingress"}, paths(u.Unknown)); diff != "" {
		t.Errorf("x.u unknown (-want +got):\n%s", diff)
	}
	if got := attr(t, u.Value, "ingress.0.proto"); !got.RawEquals(cty.StringVal("tcp")) {
		t.Errorf("ingress.0.proto = %#v", got)
	}
	if got := attr(t, u.Value, "secret.0"); !got.HasMark(terraform.SensitiveMark) {
		t.Errorf("secret.0 = %#v, want sensitive", got)
	}
	bad := res[1]
	want := []string{"extra", "iter", "lifecycle", "mixed", "noforeach", "nul", "strcontent", "twocontent"}
	if diff := cmp.Diff(want, paths(bad.Unknown)); diff != "" {
		t.Errorf("x.bad unknown (-want +got):\n%s", diff)
	}
	if got := attr(t, bad.Value, "ok"); !got.RawEquals(cty.NumberIntVal(1)) {
		t.Errorf("ok = %#v", got)
	}
	got := codes(m)
	if n := countPrefix(got, "invalid_expansion@"); n != 8 {
		t.Errorf("%d invalid_expansion diagnostics in %v, want 8", n, got)
	}
	if n := countPrefix(got, "unknown_expansion@"); n != 1 {
		t.Errorf("%d unknown_expansion diagnostics in %v, want 1", n, got)
	}
	for _, d := range m.Diagnostics {
		if strings.Contains(d.Summary+d.Detail, "5432") {
			t.Errorf("diagnostic quotes a value: %v", d)
		}
	}
}

func countPrefix(list []string, prefix string) int {
	return len(slices.DeleteFunc(slices.Clone(list), func(s string) bool { return !strings.HasPrefix(s, prefix) }))
}

// TestJSONDynamicBlockLimit: JSON entries share the per-block limit.
func TestJSONDynamicBlockLimit(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{"main.tf.json": `{"resource": {"x": {"d": {"dynamic": {"e": {
  "for_each": "${flatten([for i in range(100) : [for j in range(101) : j]])}",
  "content": {"v": "${e.value}"}
}}}}}}
`})
	if n := attr(t, res[0].Value, "e").LengthInt(); n != 10000 {
		t.Errorf("e has %d entries, want 10,000", n)
	}
	if diff := cmp.Diff([]string{"e"}, paths(res[0].Unknown)); diff != "" {
		t.Errorf("unknown (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"expansion_limit@main.tf.json:2"}, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
}

// TestJSONDynamicBlocksShareModuleLimits: JSON entries charge the module's re-evaluation work.
func TestJSONDynamicBlocksShareModuleLimits(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{"main.tf.json": `{"resource": {"x": {"r": {
  "count": 300,
  "dynamic": {"e": {
    "for_each": "${range(1000)}",
    "content": {"v": "` + strings.Repeat("x", 40) + `${e.value}"}
  }}
}}}}
`})
	limited := 0
	for _, r := range res {
		if len(r.Unknown) > 0 {
			limited++
		}
	}
	if limited == 0 || countPrefix(codes(m), "expansion_limit@") == 0 {
		t.Errorf("%d instances with unknown entries, diagnostics %v; want the module limit reached", limited, codes(m))
	}
}

// TestJSONDynamicSourceOrder: static and dynamic entries merge in source order, as hcl's
// dynblock does: here the dynamic block comes first.
func TestJSONDynamicSourceOrder(t *testing.T) {
	t.Parallel()
	_, res := decodeResources(t, map[string]string{"main.tf.json": `{"resource": {"x": {"o": {
  "dynamic": {"ingress": {"for_each": [80], "content": {"port": "${ingress.value}"}}},
  "ingress": {"port": 22}
}}}}
`})
	for path, want := range map[string]cty.Value{"ingress.0.port": cty.NumberIntVal(80), "ingress.1.port": cty.NumberIntVal(22)} {
		if got := attr(t, res[0].Value, path); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", path, got, want)
		}
	}
}

// TestJSONDynamicChargesItsSource: a dynamic block costs its whole source per instance, so
// count times a large dynamic block stops at the re-evaluation limit, as in HCL (it once cost
// one byte: 500 instances took 74s).
func TestJSONDynamicChargesItsSource(t *testing.T) {
	t.Parallel()
	var attrs []string
	for i := range 25 {
		attrs = append(attrs, fmt.Sprintf(`"a%d": "${length([%s0])}"`, i, strings.Repeat("0,", 400)))
	}
	src := `{"resource": {"x": {"r": {
  "count": 500,
  "dynamic": {"d": {"for_each": [1], "content": {` + strings.Join(attrs, ", ") + `}}}
}}}}
`
	m, res := decodeResources(t, map[string]string{"main.tf.json": src})
	if len(res) >= 500 || !slices.Contains(codes(m), "expansion_limit@main.tf.json:2") {
		t.Errorf("%d instances, diagnostics %v; want the re-evaluation limit", len(res), codes(m))
	}
}

// TestJSONDuplicateDynamicKeys: hcl's JSON syntax allows a block property to repeat, so two
// "dynamic" keys both expand.
func TestJSONDuplicateDynamicKeys(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{"main.tf.json": `{"resource": {"x": {"d": {
  "dynamic": {"a": {"for_each": [1], "content": {"v": "${a.value}"}}},
  "dynamic": {"b": {"for_each": [2], "content": {"v": "${b.value}"}}}
}}}}
`})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", m.Diagnostics)
	}
	for path, want := range map[string]cty.Value{"a.0.v": cty.NumberIntVal(1), "b.0.v": cty.NumberIntVal(2)} {
		if got := attr(t, res[0].Value, path); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", path, got, want)
		}
	}
}
