package terraform

import (
	"slices"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestNormalizeRootListsIncompleteReferences(t *testing.T) {
	rr := RootResult{
		Dir: ".",
		Instances: []*ModuleInstance{
			{
				Resources: []Resource{{
					Mode: "managed", Type: "x", Name: "a", Address: "x.a", BaseAddress: "x.a",
					Value: cty.EmptyObjectVal, ReferencesIncomplete: true,
				}},
				Outputs: map[string]Output{"o": {Name: "o", Value: cty.StringVal("v"), ReferencesIncomplete: true}},
			},
			{
				Address: "module.m",
				Outputs: map[string]Output{"p": {Name: "p", Value: cty.StringVal("v").Mark(SensitiveMark), ReferencesIncomplete: true}},
			},
			{Address: "module.skipped", Skipped: true, Resources: []Resource{{Address: "module.skipped.x.b"}}},
		},
	}
	doc, un := NormalizeRoot(rr)
	if want := []string{"module.m.output.p", "output.o", "x.a"}; !slices.Equal(un.IncompleteReferences, want) {
		t.Errorf("incomplete references %v, want %v", un.IncompleteReferences, want)
	}
	if len(doc.Resources) != 1 {
		t.Errorf("%d resources, want 1 (a skipped instance has none)", len(doc.Resources))
	}
	if len(doc.Outputs) != 2 || !doc.Outputs[1].Sensitive {
		t.Errorf("outputs %+v, want module.m's p sensitive by its value's mark", doc.Outputs)
	}
}
