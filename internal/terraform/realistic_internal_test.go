package terraform

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// limitCodes are the diagnostics that mean a limit, not the configuration, decided a value.
var limitCodes = []DiagCode{DiagExpressionTooComplex, DiagFunctionLimit, DiagModuleWorkLimit, DiagExpansionLimit}

// Realistic module trees (testdata/realistic: a for_each fan-out of 200 module instances with
// nested for expressions, nested maps flattened and looked up by key, and templatefile with
// %{ for } directives over 50 instances) evaluate fully, with at least half of the tree's
// function work, and of each module's, and of its expansion work to spare (T-0113c, ADR 0021;
// T-0113d, ADR 0022). The work each uses is
// logged for PROGRESS. nested-maps includes the lookup idiom over its 300 entries (ADR 0023).
func TestRealisticTreesStayUnderTheWorkLimit(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]struct{ instances, resources int }{
		"fanout":      {201, 400},
		"nested-maps": {1, 300},
		"templates":   {1, 50},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r, err := fsutil.OpenRoot(filepath.Join("testdata", "realistic", name))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })
			ctx := context.Background()
			limits := DefaultLimits()
			d, err := Discover(ctx, r, limits)
			if err != nil {
				t.Fatal(err)
			}
			mods, err := ClassifyModules(ctx, r, d, limits)
			if err != nil {
				t.Fatal(err)
			}
			results, err := EvaluateRoots(ctx, r, d, mods, VarOptions{}, limits, TreeOptions{})
			if err != nil {
				t.Fatal(err)
			}
			work, expansion, instances, resources := 0, 0, 0, 0
			for _, res := range results {
				for _, inst := range res.Instances {
					instances++
					work += inst.Module.fnWork
					expansion += usageOf(inst.Module).expansion // as the tree charges it, call arguments included
					if inst.Module.fnWork > maxFunctionWork/2 {
						t.Errorf("%q: function work %d is over half a module's %d", inst.Address, inst.Module.fnWork, maxFunctionWork)
					}
					for _, diag := range inst.Module.Diagnostics {
						if slices.Contains(limitCodes, diag.Code) {
							t.Errorf("%s: %v", inst.Address, diag)
						}
					}
					for _, rs := range inst.Resources {
						resources++
						if len(rs.Unknown) > 0 {
							t.Errorf("%s has unknown values %v", rs.Address, rs.Unknown)
						}
					}
				}
			}
			t.Logf("%s: %d instances, %d resources, function work %d of %d (%.1f%%)",
				name, instances, resources, work, maxTreeFunctionWork, 100*float64(work)/maxTreeFunctionWork)
			if instances != want.instances || resources != want.resources {
				t.Errorf("%d instances and %d resources, want %d and %d", instances, resources, want.instances, want.resources)
			}
			t.Logf("%s: expansion work %d of %d (%.1f%%)", name, expansion, maxTreeExpansionWork, 100*float64(expansion)/maxTreeExpansionWork)
			if expansion > maxTreeExpansionWork/2 {
				t.Errorf("expansion work %d is over half the tree's %d", expansion, maxTreeExpansionWork)
			}
			if work > maxTreeFunctionWork/2 {
				t.Errorf("function work %d is over half the tree's %d", work, maxTreeFunctionWork)
			}
		})
	}
}
