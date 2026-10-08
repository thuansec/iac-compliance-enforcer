package terraform

import (
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// TestHoldsDynamicBlockIsLinear: the walk visits each value once, so a large value wrapped in
// deep nesting costs its size, not size × depth (unmarking every subtree took 91s).
func TestHoldsDynamicBlockIsLinear(t *testing.T) {
	inner := make([]cty.Value, 2000)
	for i := range inner {
		inner[i] = cty.NumberIntVal(0)
	}
	v := cty.TupleVal(inner)
	const depth = 300
	for range depth {
		v = cty.TupleVal([]cty.Value{v})
	}
	nodes := len(inner) + depth
	allocs := testing.AllocsPerRun(3, func() {
		if holdsDynamicBlock(v) {
			t.Error("found a dynamic block")
		}
	})
	if allocs > float64(20*nodes) {
		t.Errorf("%.0f allocations for %d values, want a linear walk", allocs, nodes)
	}
	marked := cty.ObjectVal(map[string]cty.Value{"x": cty.ObjectVal(map[string]cty.Value{
		"dynamic": cty.ObjectVal(map[string]cty.Value{"b": cty.EmptyObjectVal}).Mark(SensitiveMark),
	}).Mark(SensitiveMark)})
	if !holdsDynamicBlock(marked) {
		t.Error("a marked dynamic block was not found")
	}
}
