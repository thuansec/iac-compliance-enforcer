package terraform

import (
	"slices"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestNetworkFunctions(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"u":   {Value: cty.UnknownVal(cty.String)},
		"sec": {Value: cty.StringVal("10.0.0.0/16").Mark(SensitiveMark)},
	}
	for _, c := range []struct {
		expr string
		want string // an HCL literal, "error" or "unknown"
	}{
		{`cidrsubnet("10.0.0.0/16", 8, 2)`, `"10.0.2.0/24"`},
		{`cidrsubnet("10.1.2.0/24", 4, 15)`, `"10.1.2.240/28"`},
		{`cidrsubnet("10.0.0.5/16", 8, 0)`, `"10.0.0.0/24"`}, // host bits are dropped
		{`cidrsubnet("10.0.0.0/8", 0, 0)`, `"10.0.0.0/8"`},
		{`cidrsubnet("10.0.0.0/30", 2, 3)`, `"10.0.0.3/32"`},
		{`cidrsubnet("fd00:fd12:3456:7890::/56", 16, 162)`, `"fd00:fd12:3456:7800:a200::/72"`},
		{`cidrsubnet("2001:db8::/32", 32, 1)`, `"2001:db8:0:1::/64"`},
		{`cidrsubnet("2001:db8::/32", 32, 4294967295)`, `"2001:db8:ffff:ffff::/64"`},
		{`cidrsubnet("2001:db8::/32", 33, 0)`, `error`}, // Terraform extends by at most 32 bits
		{`cidrsubnet("2001:db8::/120", 9, 0)`, `error`},
		{`cidrsubnet("10.0.0.0/16", 8, 1/0)`, `error`},
		{`cidrsubnet("::/80", 16, 65535)`, `error`},    // ::ffff:0.0.0.0/96, "0.0.0.0/0" in Terraform
		{`cidrsubnet("::/80", 24, 16776970)`, `error`}, // ::ffff:10.0.0.0/104, "10.0.0.0/8" in Terraform
		{`cidrsubnet("::/80", 16, 65534)`, `"::fffe:0:0/96"`},
		{`cidrsubnet("10.0.0.0/16", 8, 256)`, `error`},
		{`cidrsubnet("10.0.0.0/16", 8, -1)`, `error`},
		{`cidrsubnet("10.0.0.0/16", 17, 0)`, `error`},
		{`cidrsubnet("10.0.0.0/16", -1, 0)`, `error`},
		{`cidrsubnet("10.0.0.0/16", 1.5, 0)`, `error`},
		{`cidrsubnet("10.0.0.0/16", 8, 0.5)`, `error`},
		{`cidrsubnet("10.0.0.0", 8, 0)`, `error`},
		{`cidrsubnet("not a cidr", 8, 0)`, `error`},
		{`cidrsubnet("010.0.0.0/16", 8, 0)`, `error`},
		{`cidrsubnet("::ffff:10.0.0.0/104", 8, 0)`, `error`},
		{`cidrsubnet("fe80::%eth0/64", 8, 0)`, `error`},
		{`cidrsubnet(var.u, 8, 0)`, `unknown`},

		{`cidrhost("10.12.112.0/20", 16)`, `"10.12.112.16"`},
		{`cidrhost("10.12.112.0/20", 268)`, `"10.12.113.12"`},
		{`cidrhost("10.0.0.0/24", -1)`, `"10.0.0.255"`},
		{`cidrhost("10.0.0.0/24", -256)`, `"10.0.0.0"`},
		{`cidrhost("10.0.0.0/32", 0)`, `"10.0.0.0"`},
		{`cidrhost("10.0.0.0/32", -1)`, `"10.0.0.0"`},
		{`cidrhost("10.0.0.0/32", 1)`, `error`},
		{`cidrhost("0.0.0.0/0", -1)`, `"255.255.255.255"`},
		{`cidrhost("10.0.0.0/31", -2)`, `"10.0.0.0"`},
		{`cidrhost("10.0.0.0/31", -3)`, `error`},
		{`cidrhost("2001:db8::/64", -1)`, `"2001:db8::ffff:ffff:ffff:ffff"`},
		{`cidrhost("::/0", 281470849515521)`, `error`}, // ::ffff:10.0.0.1, "10.0.0.1" in Terraform
		{`cidrhost("fd00:fd12:3456:7890:00a2::/72", 34)`, `"fd00:fd12:3456:7890::22"`},
		{`cidrhost("10.0.0.0/24", 256)`, `error`},
		{`cidrhost("10.0.0.0/24", -257)`, `error`},
		{`cidrhost("10.0.0.0/24", 1.5)`, `error`},
		{`cidrhost("10.0.0.0/24", 1e40)`, `error`},
		{`cidrhost(var.u, 1)`, `unknown`},

		{`cidrnetmask("172.16.0.0/12")`, `"255.240.0.0"`},
		{`cidrnetmask("10.0.0.0/32")`, `"255.255.255.255"`},
		{`cidrnetmask("0.0.0.0/0")`, `"0.0.0.0"`},
		{`cidrnetmask("2001:db8::/32")`, `error`},
		{`cidrnetmask("10.0.0.0/33")`, `error`},
		{`cidrnetmask(var.u)`, `unknown`},
	} {
		m, got := evalLocal(t, c.expr, vars)
		switch c.want {
		case "error":
			if got.IsKnown() || !slices.Equal(diagCodes(m), []DiagCode{DiagEvaluation}) {
				t.Errorf("%s = %#v, diagnostics %v; want unknown with an evaluation warning", c.expr, got, m.Diagnostics)
			}
		case "unknown":
			if got.IsKnown() || len(m.Diagnostics) != 0 {
				t.Errorf("%s = %#v, diagnostics %v; want unknown", c.expr, got, m.Diagnostics)
			}
		default:
			if want := literal(t, c.want); len(m.Diagnostics) != 0 || !got.RawEquals(want) {
				t.Errorf("%s = %#v, diagnostics %v; want %s", c.expr, got, m.Diagnostics, c.want)
			}
		}
	}
	for _, expr := range []string{`cidrsubnet(var.sec, 8, 1)`, `cidrhost(var.sec, 1)`, `cidrnetmask(var.sec)`} {
		if _, got := evalLocal(t, expr, vars); !got.HasMark(SensitiveMark) {
			t.Errorf("%s = %#v, want sensitive", expr, got)
		}
	}
}
