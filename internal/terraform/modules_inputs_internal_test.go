package terraform

import (
	"context"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// An instance has its own function work, function table, regex cache and diagnostics: what one
// instance spends or caches never reaches another instance or the parse.
func TestNewInstanceHasItsOwnState(t *testing.T) {
	t.Parallel()
	parse := parseLocalsModule(t, `locals {
  a = upper("x")
  b = regex("[a-z]+", "abc")
}
`)
	a, b := parse.NewInstance(), parse.NewInstance()
	a.src["extra.tfvars"] = []byte("x = 1")
	if _, ok := b.src["extra.tfvars"]; ok || len(b.src) != len(parse.src) {
		t.Error("instances share their source map")
	}
	if _, err := a.EvaluateLocals(context.Background(), map[string]Variable{}); err != nil {
		t.Fatal(err)
	}
	if a.fnWork == 0 || len(a.regexes) == 0 || a.fns == nil {
		t.Errorf("instance a: work %d, %d regexes, table %v; want all set", a.fnWork, len(a.regexes), a.fns != nil)
	}
	for name, m := range map[string]*ParsedModule{"b": b, "parse": parse} {
		if m.fnWork != 0 || len(m.regexes) != 0 || m.fns != nil || m.fileBytesRead != 0 {
			t.Errorf("%s shares state: work %d, %d regexes, table %v", name, m.fnWork, len(m.regexes), m.fns != nil)
		}
	}
	// The function table is bound to its own instance: b's work is charged to b.
	locals, err := b.EvaluateLocals(context.Background(), map[string]Variable{})
	if err != nil {
		t.Fatal(err)
	}
	if !locals["a"].Value.RawEquals(cty.StringVal("X")) || b.fnWork == 0 {
		t.Errorf("instance b: a = %#v, work %d", locals["a"].Value, b.fnWork)
	}
}
