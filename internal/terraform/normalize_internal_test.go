package terraform

import (
	"encoding/json/v2"
	"math/big"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

func encodeJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(data)
}

func TestNormalizeListsUnknownsTheEvaluatorMissed(t *testing.T) {
	r := Resource{
		Mode: "managed", Type: "x_thing", Name: "t", Address: "x_thing.t", BaseAddress: "x_thing.t",
		Value: cty.ObjectVal(map[string]cty.Value{
			"a": cty.UnknownVal(cty.String),
			"b": cty.ListVal([]cty.Value{cty.StringVal("x"), cty.UnknownVal(cty.String)}),
			"c": cty.StringVal("known"),
		}),
		// The evaluator listed only a; b[1] must still be reported.
		Unknown: []cty.Path{cty.GetAttrPath("a")},
	}
	got, complete := NormalizeResource(r)
	if !complete {
		t.Fatal("complete = false")
	}
	if s, want := encodeJSON(t, got.Unknown), `[["a"],["b",1]]`; s != want {
		t.Errorf("unknown %s, want %s", s, want)
	}
}

func TestNormalizePathsIntoSetsCoverTheSet(t *testing.T) {
	set := cty.SetVal([]cty.Value{
		cty.ObjectVal(map[string]cty.Value{"port": cty.NumberIntVal(22)}).Mark(SensitiveMark),
		cty.ObjectVal(map[string]cty.Value{"port": cty.NumberIntVal(443)}),
	})
	r := Resource{
		Mode: "managed", Type: "x_thing", Name: "t", Address: "x_thing.t", BaseAddress: "x_thing.t",
		Value: cty.ObjectVal(map[string]cty.Value{
			"rules": set,
			// A path whose IndexStep key is a string must follow the type: here a map key.
			"labels": cty.MapVal(map[string]cty.Value{"env": cty.StringVal("x").Mark(SensitiveMark)}),
		}),
		// A path that steps into a set element is reported as the set.
		Unknown: []cty.Path{cty.GetAttrPath("rules").Index(cty.ObjectVal(map[string]cty.Value{"port": cty.NumberIntVal(22)})).GetAttr("port")},
	}
	got, _ := NormalizeResource(r)
	if s, want := encodeJSON(t, got.Unknown), `[["rules"]]`; s != want {
		t.Errorf("unknown %s, want %s", s, want)
	}
	if s, want := encodeJSON(t, got.Sensitive), `[["labels","env"],["rules"]]`; s != want {
		t.Errorf("sensitive %s, want %s", s, want)
	}
	if s, want := encodeJSON(t, got.Values["rules"]), `null`; s != want {
		t.Errorf("rules %s, want null (listed unknown)", s)
	}
}

func TestNormalizeWhollyUnknownValueIsIncomplete(t *testing.T) {
	for name, v := range map[string]cty.Value{
		"unknown":    cty.DynamicVal,
		"null":       cty.NullVal(cty.EmptyObject),
		"not object": cty.StringVal("x"),
	} {
		t.Run(name, func(t *testing.T) {
			r := Resource{Mode: "managed", Type: "x", Name: "t", Address: "x.t", BaseAddress: "x.t", Value: v}
			got, complete := NormalizeResource(r)
			if complete {
				t.Error("complete = true for a value that is not a known object")
			}
			if s := encodeJSON(t, got.Values); s != "{}" {
				t.Errorf("values %s, want {}", s)
			}
		})
	}
}

func TestNormalizeNumbers(t *testing.T) {
	huge := new(big.Float).SetPrec(8192).SetMantExp(big.NewFloat(1), 5000)  // 2^5000
	tiny := new(big.Float).SetPrec(8192).SetMantExp(big.NewFloat(1), -5000) // 2^-5000
	third := new(big.Float).SetPrec(8192).Quo(big.NewFloat(1).SetPrec(8192), big.NewFloat(3).SetPrec(8192))
	for _, tc := range []struct {
		name string
		v    *big.Float
		want string
		ok   bool
	}{
		{"int64 max", new(big.Float).SetInt64(1<<63 - 1), "9223372036854775807", true},
		{"int64 min", new(big.Float).SetInt64(-1 << 63), "-9223372036854775808", true},
		{"beyond int64", new(big.Float).SetPrec(512).SetMantExp(big.NewFloat(1), 70), "1.1805916207174113e+21", true},
		{"negative zero", new(big.Float).Neg(new(big.Float)), "0", true},
		{"third at 8192 bits", third, "0.3333333333333333", true},
		{"2^5000", huge, "", false},
		{"2^-5000", tiny, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := normalizeNumber(tc.v)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok {
				if s := encodeJSON(t, got); s != tc.want {
					t.Errorf("got %s, want %s", s, tc.want)
				}
			}
		})
	}
}

// TestNormalizeHighPrecisionNumbersIsBounded shows that normalization never formats a number
// exactly: 10,000 numbers with 8,192 fractional bits, which would take about 2.4 ms each to
// format exactly (ADR 0043), normalize in well under a second.
func TestNormalizeHighPrecisionNumbersIsBounded(t *testing.T) {
	third := new(big.Float).SetPrec(8192).Quo(big.NewFloat(1).SetPrec(8192), big.NewFloat(3).SetPrec(8192))
	elems := make([]cty.Value, 10_000)
	for i := range elems {
		elems[i] = cty.NumberVal(third)
	}
	r := Resource{
		Mode: "managed", Type: "x", Name: "t", Address: "x.t", BaseAddress: "x.t",
		Value: cty.ObjectVal(map[string]cty.Value{"n": cty.TupleVal(elems)}),
	}
	start := time.Now()
	if _, complete := NormalizeResource(r); !complete {
		t.Fatal("complete = false")
	}
	if d := time.Since(start); d > time.Second*raceSlowdown {
		t.Errorf("normalizing took %v", d)
	}
}

func TestModelPathFollowsTheType(t *testing.T) {
	ty := cty.Object(map[string]cty.Type{
		"list":  cty.List(cty.Object(map[string]cty.Type{"a": cty.String})),
		"tuple": cty.Tuple([]cty.Type{cty.String, cty.Number}),
		"set":   cty.Set(cty.String),
		"map":   cty.Map(cty.String),
	})
	for _, tc := range []struct {
		name string
		path cty.Path
		want string
	}{
		{"list element attribute", cty.GetAttrPath("list").IndexInt(2).GetAttr("a"), `["list",2,"a"]`},
		{"object attribute by index step", cty.IndexStringPath("tuple").IndexInt(1), `["tuple",1]`},
		{"tuple index past the end", cty.GetAttrPath("tuple").IndexInt(5), `["tuple",5]`},
		{"negative index stops before it", cty.GetAttrPath("list").Index(cty.NumberIntVal(-1)), `["list"]`},
		{"fractional index stops before it", cty.GetAttrPath("list").Index(cty.NumberFloatVal(1.5)), `["list"]`},
		{"unknown key stops before it", cty.GetAttrPath("map").Index(cty.UnknownVal(cty.String)), `["map"]`},
		{"set element is the set", cty.GetAttrPath("set").Index(cty.StringVal("a")), `["set"]`},
		{"attribute of a list stops at the list", cty.GetAttrPath("list").GetAttr("a"), `["list"]`},
		{"missing attribute is the whole value", cty.GetAttrPath("nope"), `null`},
		{"empty path is the whole value", cty.Path{}, `null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := modelPath(ty, tc.path)
			if tc.want == "null" {
				if got != nil {
					t.Errorf("got %s, want nil (the whole value)", encodeJSON(t, got))
				}
				return
			}
			if s := encodeJSON(t, got); s != tc.want {
				t.Errorf("got %s, want %s", s, tc.want)
			}
		})
	}
}

func TestOutermostSortsAndDropsCoveredPaths(t *testing.T) {
	set := map[string]model.Path{}
	n := normalizer{}
	for _, p := range []model.Path{
		{model.AttrStep("b"), model.IndexStep(1)},
		{model.AttrStep("a"), model.AttrStep("x")},
		{model.AttrStep("b")},
		{model.AttrStep("a"), model.IndexStep(0)},
		{model.AttrStep("a"), model.AttrStep("x"), model.AttrStep("y")},
	} {
		n.add(set, p)
	}
	n.add(set, nil)
	if s, want := encodeJSON(t, outermost(set)), `[["a",0],["a","x"],["b"]]`; s != want {
		t.Errorf("got %s, want %s", s, want)
	}
}

func TestNormalizeWholeValueUnknownOrSensitive(t *testing.T) {
	obj := cty.ObjectVal(map[string]cty.Value{
		"a": cty.StringVal("FAKE"),
		"b": cty.NullVal(cty.String),
		"c": cty.ListVal([]cty.Value{cty.StringVal("x")}),
	})
	base := Resource{Mode: "managed", Type: "x", Name: "t", Address: "x.t", BaseAddress: "x.t"}

	t.Run("listed empty path", func(t *testing.T) {
		r := base
		r.Value, r.Unknown = obj, []cty.Path{{}}
		if _, complete := NormalizeResource(r); complete {
			t.Error("complete = true although the evaluator reports the whole value unknown")
		}
	})
	t.Run("listed path that does not match the type", func(t *testing.T) {
		r := base
		r.Value, r.Unknown = obj, []cty.Path{cty.GetAttrPath("missing")}
		if _, complete := NormalizeResource(r); complete {
			t.Error("complete = true for an unknown path the value cannot hold")
		}
	})
	t.Run("sensitive mark on the whole value", func(t *testing.T) {
		r := base
		r.Value = obj.Mark(SensitiveMark)
		got, complete := NormalizeResource(r)
		if !complete {
			t.Fatal("complete = false")
		}
		if s, want := encodeJSON(t, got.Sensitive), `[["a"],["b"],["c"]]`; s != want {
			t.Errorf("sensitive %s, want %s", s, want)
		}
	})
	t.Run("listed unknown on a known null attribute", func(t *testing.T) {
		r := base
		r.Value, r.Unknown = obj, []cty.Path{cty.GetAttrPath("b")}
		got, _ := NormalizeResource(r)
		if s, want := encodeJSON(t, got.Values), `{"a":"FAKE","b":null,"c":["x"]}`; s != want {
			t.Errorf("values %s, want %s", s, want)
		}
	})
}

func TestNormalizeDoesNotShareLifecycle(t *testing.T) {
	r := Resource{
		Mode: "managed", Type: "x", Name: "t", Address: "x.t", BaseAddress: "x.t",
		Value:     cty.EmptyObjectVal,
		Lifecycle: model.Lifecycle{IgnoreChanges: []string{"tags"}},
	}
	got, _ := NormalizeResource(r)
	r.Lifecycle.IgnoreChanges[0] = "changed"
	if got.Meta.Lifecycle.IgnoreChanges[0] != "tags" {
		t.Error("normalized lifecycle shares the evaluator's ignore_changes")
	}
}
