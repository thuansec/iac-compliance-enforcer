package terraform

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zclconf/go-cty/cty"
)

func TestMergeUnknown(t *testing.T) {
	t.Parallel()
	attr := func(names ...string) cty.Path {
		var p cty.Path
		for _, n := range names {
			p = p.GetAttr(n)
		}
		return p
	}
	base := []cty.Path{attr("a"), attr("b").Index(cty.NumberIntVal(0)).GetAttr("x"), attr("c").Index(cty.NumberIntVal(10)), attr("c").Index(cty.NumberIntVal(2))}
	extra := []cty.Path{attr("b"), attr("b", "y"), attr("d")}
	got := mergeUnknown(base, extra)
	want := []cty.Path{attr("a"), attr("b"), attr("c").Index(cty.NumberIntVal(2)), attr("c").Index(cty.NumberIntVal(10)), attr("d")}
	if diff := cmp.Diff(want, got, cmp.Comparer(func(a, b cty.Path) bool { return a.Equals(b) })); diff != "" {
		t.Errorf("mergeUnknown (-want +got):\n%s", diff)
	}
	if got := mergeUnknown(base, nil); len(got) != len(base) {
		t.Errorf("mergeUnknown without extra changed base: %v", got)
	}
}
