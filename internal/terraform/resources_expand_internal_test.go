package terraform

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// decodeSource decodes the resources of a module whose main.tf is src.
func decodeSource(t *testing.T, src string) (*ParsedModule, []Resource) {
	t.Helper()
	m := parseLocalsModule(t, src)
	res, err := m.DecodeResources(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m, res
}

func limitDiags(m *ParsedModule) []string {
	var out []string
	for _, d := range m.Diagnostics {
		out = append(out, fmt.Sprintf("%s@%d", d.Code, d.Line))
	}
	return out
}

// TestExpansionWorkBoundary: every instance after the first evaluates the attribute again
// (cost 1 + its source bytes), so the instances stop exactly where maxExpansionWork runs out.
func TestExpansionWorkBoundary(t *testing.T) {
	t.Parallel()
	line := `a = "` + strings.Repeat("x", 900) + `"`
	cost := 1 + len(line)
	limit := 1 + maxExpansionWork/cost // the first instance is not charged
	for _, c := range []struct {
		count, want int
		limited     bool
	}{
		{limit - 1, limit - 1, false},
		{limit, limit, false},
		{limit + 1, limit, true},
	} {
		m, res := decodeSource(t, fmt.Sprintf("resource \"x\" \"w\" {\n  count = %d\n  %s\n}\n", c.count, line))
		if len(res) != c.want || c.limited != (len(m.Diagnostics) == 1) {
			t.Errorf("count %d: %d instances, diagnostics %v; want %d (limited %v)", c.count, len(res), limitDiags(m), c.want, c.limited)
		}
	}
}

// TestInstanceStructureLimit: instances with many nested blocks stop at the module's
// structure estimate, and every resource cut short is reported.
func TestInstanceStructureLimit(t *testing.T) {
	t.Parallel()
	big := fmt.Sprintf("resource \"x\" \"r1\" {\n  count = 10000\n%s}\n", strings.Repeat("  a {}\n", 40))
	src := big + "\n" + strings.Replace(big, `"r1"`, `"r2"`, 1) + "\nresource \"x\" \"r3\" {\n  count = 10000\n}\n"
	m, res := decodeSource(t, src)
	bigCost := instanceStructure(m.Blocks[0].Body.(*hclsyntax.Body))
	smallCost := instanceStructure(m.Blocks[2].Body.(*hclsyntax.Body))
	n1 := maxInstanceStructure / bigCost
	n3 := (maxInstanceStructure - n1*bigCost) / smallCost
	counts := map[string]int{}
	for _, r := range res {
		counts[r.BaseAddress]++
	}
	if counts["x.r1"] != n1 || counts["x.r2"] != 0 || counts["x.r3"] != n3 || n1 >= 10000 || n3 >= 10000 {
		t.Errorf("instances %v, want x.r1 %d, x.r2 0, x.r3 %d", counts, n1, n3)
	}
	// Each resource cut short is reported at its count.
	if got := strings.Join(limitDiags(m), " "); got != "expansion_limit@2 expansion_limit@46 expansion_limit@90" {
		t.Errorf("diagnostics %s", got)
	}
}

// TestExpansionHeap: at the module limits, the decoded instances of a small file stay well
// within the scan's memory budget. The live heap of each shape is logged for PROGRESS.
func TestExpansionHeap(t *testing.T) {
	shapes := map[string]string{
		"bare": "",
		"attributes": func() string {
			var b strings.Builder
			for i := range 20 {
				fmt.Fprintf(&b, "  a%d = 1\n", i)
			}
			return b.String()
		}(),
		"blocks": strings.Repeat("  a {}\n", 20),
		"nested": "  a {\n    b {\n      c {}\n    }\n  }\n",
	}
	for name, body := range shapes {
		var b strings.Builder
		for i := range 10 {
			fmt.Fprintf(&b, "resource \"x\" \"r%d\" {\n  count = 10000\n%s}\n", i, body)
		}
		m := parseLocalsModule(t, b.String())
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		res, err := m.DecodeResources(context.Background(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		live := int64(after.HeapAlloc) - int64(before.HeapAlloc)
		t.Logf("%s: %d instances, %d MB live", name, len(res), live>>20)
		if live > 192<<20 {
			t.Errorf("%s: %d instances hold %d MB, want under 192 MB", name, len(res), live>>20)
		}
		runtime.KeepAlive(res)
	}
}
