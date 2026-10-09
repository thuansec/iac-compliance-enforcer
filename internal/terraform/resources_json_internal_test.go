package terraform

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/json"
)

// TestHoldsDynamicSource: a "dynamic" key with an object or array value, at any depth of a JSON
// value's source, marks a nested block; other values are data.
func TestHoldsDynamicSource(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat(`{"a": [`, 40) + `{"dynamic": {"x": {}}}` + strings.Repeat(`]}`, 40)
	for src, want := range map[string]bool{
		`{"dynamic": {"x": {"for_each": [1]}}}`:          true,
		`{"dynamic": [{"x": {}}]}`:                       true,
		`[1, {"b": {"dynamic": {"x": {}}}}]`:             true,
		deep:                                             true,
		`{"dynamic": {}}`:                                true,
		`{"dynamic": []}`:                                true,
		`{"dynamic": null}`:                              false,
		`{"dynamic": "a string is data"}`:                false,
		`{"dynamic": 1}`:                                 false,
		`{"${var.k}": {"x": 1}}`:                         false,
		`"${local.m}"`:                                   false,
		`{"tags": {"Name": "web"}, "list": [1, 2, "x"]}`: false,
	} {
		f, diags := json.Parse([]byte(`{"v": `+src+`}`), "t.json")
		if diags.HasErrors() {
			t.Fatalf("%s: %v", src, diags)
		}
		attrs, _ := f.Body.JustAttributes()
		if got := (&resourceDecoder{}).holdsDynamicSource(attrs["v"].Expr); got != want {
			t.Errorf("%.40s: %v, want %v", src, got, want)
		}
	}
}

// TestJSONBodyCost: a JSON body costs jsonEvalFactor per byte of its attributes and of its
// dynamic blocks, each from its "dynamic" key to its closing brace (its own DefRange is only
// its opening brace).
func TestJSONBodyCost(t *testing.T) {
	t.Parallel()
	attr := `"a": "${x}"`
	dyn := `"dynamic": {"d": {"for_each": [1], "content": {"v": 1}}}`
	f, diags := json.Parse([]byte(`{`+attr+`, "count": 2, `+dyn+`}`), "t.json")
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	jb, diags := parseJSONBody(f.Body, true)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	// The block ends at its own closing brace, one before the property's.
	if got, want := jb.cost(true), 1+jsonEvalFactor*(len(attr)+len(dyn)-1); got != want {
		t.Errorf("cost %d, want %d", got, want)
	}
}

// TestJSONDynamicDetectionIsLinear: each nesting level asks whether the values below it hold a
// dynamic block; memoized, deep nesting over a large value costs about what one level does
// (unmemoized, depth 400 over 2.4 MB took 111s).
func TestJSONDynamicDetectionIsLinear(t *testing.T) {
	blob := "[" + strings.Repeat("0,", 20000) + "0]"
	alloc := func(depth int) uint64 {
		src := strings.Repeat(`{"p": `, depth) + `{"blob": ` + blob + `, "dynamic": {"x": {"for_each": [1], "content": {}}}}` + strings.Repeat(`}`, depth)
		m := parseFilesModule(t, map[string]string{"main.tf.json": `{"resource": {"x": {"y": {"p": ` + src + `}}}}`})
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		res, err := m.DecodeResources(context.Background(), nil, nil)
		runtime.ReadMemStats(&after)
		if err != nil || len(res) != 1 || len(res[0].Unknown) != 0 {
			t.Fatalf("depth %d: %v, %+v", depth, err, res)
		}
		return after.TotalAlloc - before.TotalAlloc
	}
	shallow, deep := alloc(1), alloc(100)
	if deep > 3*shallow+(4<<20) {
		t.Errorf("depth 100 allocated %d bytes, depth 1 %d; want about the same", deep, shallow)
	}
}

// TestHoldsDynamicSourceScalarsAreCheap: only objects and arrays are walked into and memoized;
// a scalar is data at once. A flat 2.4 MB array allocated about 2.4 GB and kept a memo entry
// per element when every scalar was tried as a map and a list (T-0106e review).
func TestHoldsDynamicSourceScalarsAreCheap(t *testing.T) {
	src := "[" + strings.Repeat("0,", 1_200_000) + "0]"
	f, diags := json.Parse([]byte(`{"v": `+src+`}`), "t.json")
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	attrs, _ := f.Body.JustAttributes()
	d := &resourceDecoder{}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	found := d.holdsDynamicSource(attrs["v"].Expr)
	runtime.ReadMemStats(&after)
	if found {
		t.Error("a flat array holds no dynamic block")
	}
	// Listing the elements costs about 16 bytes per source byte; trying each as a map and a
	// list cost about 1,000.
	if got, limit := after.TotalAlloc-before.TotalAlloc, uint64(32*len(src)); got > limit {
		t.Errorf("allocated %d bytes, want at most %d", got, limit)
	}
	if len(d.dynamicSource) != 1 {
		t.Errorf("%d memo entries, want 1 (the array)", len(d.dynamicSource))
	}
}
