package terraform

import (
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// cty decides a call's type before calling it, and skips the call when an argument is unknown
// and its parameter does not allow that. The bounded wrapper measures the arguments in the type
// pass, so a skipped call walked its arguments for free (T-0114h review). The type pass now
// charges that walk when the call will be skipped, and only then, so calls that run are charged
// once, in the call (T-0114j). Locals and for expressions also charge the values they use
// (ADR 0020, ADR 0026), so this is the call-level layer under them.
func TestSkippedCallsPayForTheirArguments(t *testing.T) {
	t.Parallel()
	big := tupleOf(60_000, cty.StringVal("a"))
	size, _ := valueSize(big, maxFunctionWork, maxNesting)
	unknown := cty.UnknownVal(cty.Number)
	idxSize, _ := valueSize(unknown, maxFunctionWork, maxNesting)

	m := &ParsedModule{}
	element := m.functions(nil, nil)["element"]
	for i := range 10 {
		before := m.fnWork
		v, err := element.Call([]cty.Value{big, unknown})
		if err != nil {
			t.Fatal(err)
		}
		if v.IsKnown() {
			t.Fatalf("call %d: known result for an unknown index", i)
		}
		if got := m.fnWork - before; got != size+idxSize {
			t.Errorf("call %d: charged %d, want the arguments' size %d", i, got, size+idxSize)
		}
	}

	// A call that runs pays its arguments and result in the call, not again in the type pass.
	m = &ParsedModule{}
	element = m.functions(nil, nil)["element"]
	if _, err := element.Call([]cty.Value{big, cty.NumberIntVal(3)}); err != nil {
		t.Fatal(err)
	}
	if want := size + 2 + 2; m.fnWork != want { // arguments, then the result "a" (2 units)
		t.Errorf("a call that runs: charged %d, want %d", m.fnWork, want)
	}
}

// A skipped call whose arguments pass the size limit pays the limit, the most measuring could
// walk, each time: before, it paid nothing unless the function built sets.
func TestSkippedCallsOverTheLimitPayTheLimit(t *testing.T) {
	t.Parallel()
	big := tupleOf(140_000, cty.StringVal("a")) // 280,001 units: over maxFunctionValueSize
	m := &ParsedModule{}
	element := m.functions(nil, nil)["element"]
	for i := range 3 {
		m.fnLimited = false
		before, limit := m.fnWork, m.functionArgsLimit()
		v, err := element.Call([]cty.Value{big, cty.UnknownVal(cty.Number)})
		if err != nil {
			t.Fatal(err)
		}
		if v.IsKnown() || !m.fnLimited {
			t.Errorf("call %d: known %v, limited %v; want unknown and limited", i, v.IsKnown(), m.fnLimited)
		}
		if got := m.fnWork - before; got != limit {
			t.Errorf("call %d: charged %d, want the limit %d", i, got, limit)
		}
	}
}

// An unknown argument in a variadic position skips the call too.
func TestSkippedVariadicCallsPayForTheirArguments(t *testing.T) {
	t.Parallel()
	big := tupleOf(1_000, cty.StringVal("a"))
	unknown := cty.UnknownVal(cty.List(cty.String))
	size, _ := measureArgs([]cty.Value{big, unknown}, maxFunctionWork)
	m := &ParsedModule{}
	if _, err := m.functions(nil, nil)["concat"].Call([]cty.Value{big, unknown}); err != nil {
		t.Fatal(err)
	}
	if want := size[0] + size[1]; m.fnWork != want {
		t.Errorf("charged %d, want the arguments' size %d", m.fnWork, want)
	}
}

// A call whose type pass fails never runs, and can and try catch the error, so the failure pays
// for the arguments it measured.
func TestFailedCallsPayForTheirArguments(t *testing.T) {
	t.Parallel()
	big := tupleOf(60_000, cty.StringVal("a"))
	bad := cty.EmptyObjectVal // not a number: converting the index fails
	sizes, _ := measureArgs([]cty.Value{big, bad}, maxFunctionWork)
	m := &ParsedModule{}
	element := m.functions(nil, nil)["element"]
	for i := range 3 {
		before := m.fnWork
		if _, err := element.Call([]cty.Value{big, bad}); err == nil {
			t.Fatal("no error for an object index")
		}
		if got := m.fnWork - before; got != sizes[0]+sizes[1] {
			t.Errorf("call %d: charged %d, want %d", i, got, sizes[0]+sizes[1])
		}
	}
	// The arguments convert (concat takes any type), but concat's own type pass rejects a
	// string.
	str := cty.StringVal("x")
	sizes, _ = measureArgs([]cty.Value{big, str}, maxFunctionWork)
	concat := m.functions(nil, nil)["concat"]
	for i := range 3 {
		before := m.fnWork
		if _, err := concat.Call([]cty.Value{big, str}); err == nil {
			t.Fatal("no error for a string in concat")
		}
		if got := m.fnWork - before; got != sizes[0]+sizes[1] {
			t.Errorf("concat call %d: charged %d, want %d", i, got, sizes[0]+sizes[1])
		}
	}
}
