package terraform_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// setWalkModule declares a set(number) default of the given elements and 32 locals that each
// take the whole set, so the set is walked once per local.
func setWalkModule(elems []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "variable \"s\" {\n  type    = set(number)\n  default = [%s]\n}\n\nlocals {\n", strings.Join(elems, ", "))
	for i := range 32 {
		fmt.Fprintf(&b, "  l%d = var.s\n", i)
	}
	b.WriteString("}\n")
	return b.String()
}

// TestFirstSortOfAFractionSetIsBounded is the regression test of ADR 0047: cty sorts a set
// before any accessor returns its elements, so the first sort of a set of fractions is not
// counted (about 1 s for 2,000 512-bit fractions), but it happens once per set value a module
// evaluation measures, and the locals that take the set are refused instead of each paying for
// it.
func TestFirstSortOfAFractionSetIsBounded(t *testing.T) { // not parallel: it measures time
	elems := make([]string, 2000)
	for i := range elems {
		elems[i] = fmt.Sprintf("%d.1", i)
	}
	dir := files(t, map[string]string{"main.tf": setWalkModule(elems)})
	start := time.Now()
	instances := mustEvaluateTree(t, dir)
	if elapsed := time.Since(start); elapsed > 5*time.Second*raceSlowdown {
		t.Errorf("took %v; the first sort is bounded at about one per module evaluation", elapsed)
	}
	if v := instances[0].Variables["s"].Value; !v.IsWhollyKnown() || v.LengthInt() != 2000 {
		t.Fatal("the set of 2,000 fractions did not convert, so the test would not exercise its sort")
	}
	locals := instances[0].Locals
	refused := 0
	for i := range 32 {
		if l, ok := locals[fmt.Sprintf("l%d", i)]; ok && !l.Value.IsWhollyKnown() {
			refused++
		}
	}
	if refused != 32 {
		t.Errorf("%d of 32 locals refused, want all of them (too large to walk again)", refused)
	}
	if !slices.ContainsFunc(instances[0].Module.Diagnostics, func(d terraform.Diagnostic) bool {
		return d.Code == terraform.DiagValueTooLarge && d.Summary == "Local value too large"
	}) {
		t.Errorf("no \"Local value too large\" diagnostic: %v", instances[0].Module.Diagnostics)
	}
}

// TestIntegerSetWalksAreAccepted keeps the reason for option (b) of the set-sort decision:
// integer sets are not priced as fractions. A set(number) of 4,000 integers converts, and the
// locals that take it are accepted until their integer-priced sorts, spent from the module's
// function work, use it up (20 of 32 on main @ abfdd4f), where pricing every element as a
// 512-bit fraction would refuse the set itself at conversion.
func TestIntegerSetWalksAreAccepted(t *testing.T) {
	t.Parallel()
	elems := make([]string, 4000)
	for i := range elems {
		elems[i] = fmt.Sprint(i)
	}
	instances := mustEvaluateTree(t, files(t, map[string]string{"main.tf": setWalkModule(elems)}))
	inst := instances[0]
	if v := inst.Variables["s"].Value; !v.IsWhollyKnown() || v.LengthInt() != 4000 {
		t.Fatal("the set of 4,000 integers did not convert")
	}
	accepted := 0
	for i := range 32 {
		if l, ok := inst.Locals[fmt.Sprintf("l%d", i)]; ok && l.Value.IsWhollyKnown() && l.Value.LengthInt() == 4000 {
			accepted++
		}
	}
	if accepted < 20 {
		t.Errorf("%d of 32 locals accepted the set of 4,000 integers, want at least 20", accepted)
	}
	for _, d := range inst.Module.Diagnostics {
		if d.Code != terraform.DiagValueTooLarge {
			t.Errorf("unexpected diagnostic %s: %s", d.Code, d.Summary)
		}
	}
}

// TestFractionSetPassedToModuleInstancesIsBounded covers the repeat ADR 0047 does not accept:
// passing the set to every instance of a module call walked it once per instance with the sort
// uncounted, about 1 s each (62 s for count = 64; T-0124e review). The caller's measurement of
// var.s is now shared by every instance's arguments (resourceDecoder.shared): it is walked once,
// and its cached "too large" result refuses the argument in every instance.
func TestFractionSetPassedToModuleInstancesIsBounded(t *testing.T) { // not parallel: it measures time
	elems := make([]string, 2000)
	for i := range elems {
		elems[i] = fmt.Sprintf("%d.1", i)
	}
	dir := files(t, map[string]string{
		"main.tf": fmt.Sprintf("variable \"s\" {\n  type    = set(number)\n  default = [%s]\n}\n\n"+
			"module \"m\" {\n  source = \"./child\"\n  count  = 32\n  s      = var.s\n}\n", strings.Join(elems, ", ")),
		"child/main.tf": "variable \"s\" {\n  type = any\n}\n",
	})
	start := time.Now()
	mustEvaluateTree(t, dir)
	if elapsed := time.Since(start); elapsed > 5*time.Second*raceSlowdown {
		t.Errorf("took %v; each instance re-sorted the set uncounted", elapsed)
	}
}

// TestAcceptedModuleArgumentsSpendTheirSorts covers a set small enough to pass to the instances:
// each accepted argument walk sorts it in full, so evalBounded spends that sort from the caller's
// function work, and once it runs out the later instances get an unknown value with a warning
// instead of another uncounted walk (T-0124e review).
func TestAcceptedModuleArgumentsSpendTheirSorts(t *testing.T) {
	t.Parallel()
	elems := make([]string, 200)
	for i := range elems {
		elems[i] = fmt.Sprintf("%d.1", i)
	}
	instances := mustEvaluateTree(t, files(t, map[string]string{
		"main.tf": fmt.Sprintf("variable \"s\" {\n  type    = set(number)\n  default = [%s]\n}\n\n"+
			"module \"m\" {\n  source = \"./child\"\n  count  = 32\n  s      = var.s\n}\n", strings.Join(elems, ", ")),
		"child/main.tf": "variable \"s\" {\n  type = any\n}\n",
	}))
	received, refused := 0, 0
	for _, inst := range instances[1:] {
		if inst.Variables["s"].Value.IsWhollyKnown() {
			received++
		} else {
			refused++
		}
	}
	if received == 0 || refused == 0 {
		t.Errorf("%d instances received the set, %d were refused; want the first ones to receive it and the "+
			"caller's function work to stop the rest", received, refused)
	}
	if !slices.ContainsFunc(instances[0].Module.Diagnostics, func(d terraform.Diagnostic) bool {
		return d.Code == terraform.DiagValueTooLarge || d.Code == terraform.DiagFunctionLimit
	}) {
		t.Errorf("no warning for the refused arguments: %v", instances[0].Module.Diagnostics)
	}
}
