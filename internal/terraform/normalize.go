package terraform

import (
	"cmp"
	"maps"
	"math"
	"math/big"
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// NormalizeResource converts an evaluated resource into the input document's resource
// (iace-architecture/references/input-document.md, ADR 0045). Unknown values are null and
// listed in unknown, including any the evaluator did not list; sensitive marks become sensitive
// paths; a path that steps into a set covers the whole set, since set elements have no stable
// index, and a mark on the whole value covers every attribute. complete is false when the value
// as a whole is not a known object, or the evaluator reports it wholly unknown: no path can say
// that everything is unknown, so the caller must record it as a coverage gap.
func NormalizeResource(r Resource) (res model.Resource, complete bool) {
	res = model.Resource{
		Address:        r.Address,
		BaseAddress:    r.BaseAddress,
		Mode:           r.Mode,
		Type:           r.Type,
		Name:           r.Name,
		Index:          r.Index,
		Module:         r.Module,
		Provider:       r.Provider,
		ProviderConfig: r.ProviderConfig,
		Values:         model.Values{},
		Unknown:        []model.Path{},
		Sensitive:      []model.Path{},
		References:     map[string][]string{},
		Meta: model.ResourceMeta{
			CountUnknown:   r.CountUnknown,
			ForEachUnknown: r.ForEachUnknown,
			DependsOn:      append([]string{}, r.DependsOn...),
			Lifecycle: model.Lifecycle{
				PreventDestroy: r.Lifecycle.PreventDestroy,
				IgnoreChanges:  slices.Clone(r.Lifecycle.IgnoreChanges),
			},
		},
		Source: model.ResourceSource{
			File:       r.File,
			Range:      modelRange(r.Range),
			Attributes: make(map[string]model.Range, len(r.Attributes)),
		},
	}
	for path, targets := range r.References {
		res.References[path] = slices.Sorted(slices.Values(targets))
	}
	for path, rng := range r.Attributes {
		res.Source.Attributes[path] = modelRange(rng)
		// An override file merges its attributes into the base block (ADR 0048).
		if rng.Filename != "" && rng.Filename != r.File {
			if res.Source.AttributeFiles == nil {
				res.Source.AttributeFiles = map[string]string{}
			}
			res.Source.AttributeFiles[path] = rng.Filename
		}
	}
	if r.CallFile != "" {
		res.Source.ModuleCall = &model.SourceLocation{File: r.CallFile, Range: modelRange(r.CallRange)}
	}

	value, marks := r.Value.UnmarkDeepWithPaths()
	if !value.IsKnown() || value.IsNull() || !value.Type().IsObjectType() {
		return res, false
	}
	n := normalizer{unknown: map[string]model.Path{}}
	for _, p := range r.Unknown {
		mp := modelPath(value.Type(), p)
		if mp == nil {
			// The evaluator reports the whole value as unknown (unknownPaths collapses many
			// paths into the empty one), which no path can express.
			return res, false
		}
		n.add(n.unknown, mp)
	}
	sensitive := map[string]model.Path{}
	for _, pm := range marks {
		if _, ok := pm.Marks[SensitiveMark]; !ok {
			continue
		}
		mp := modelPath(value.Type(), pm.Path)
		if mp == nil {
			// A mark on the whole value covers every attribute.
			for name := range value.Type().AttributeTypes() {
				n.add(sensitive, model.Path{model.AttrStep(name)})
			}
			continue
		}
		n.add(sensitive, mp)
	}
	for name, v := range value.AsValueMap() {
		if out, keep := n.value(model.Path{model.AttrStep(name)}, v, true); keep {
			res.Values[name] = out
		}
	}
	res.Unknown = outermost(n.unknown)
	res.Sensitive = outermost(sensitive)
	// A listed unknown path is null in values, even where the walk found it known or omitted it
	// as a known null attribute.
	for _, p := range res.Unknown {
		clearPath(res.Values, p)
	}
	return res, true
}

// normalizer converts cty values into JSON values and records the unknown paths it meets.
type normalizer struct {
	unknown map[string]model.Path
}

// add records p in set under a key that tells names from indexes; a nil p is not recorded.
func (n *normalizer) add(set map[string]model.Path, p model.Path) {
	if p == nil {
		return
	}
	set[pathKey(p)] = p
}

// value converts v, found at path, into a JSON value: nil where it is unknown. keep is false
// for a known null object attribute (attr), which Terraform treats as absent (contract rule 3);
// a null list or map element is kept, since its position or key is data.
func (n *normalizer) value(path model.Path, v cty.Value, attr bool) (out any, keep bool) {
	if v.IsNull() {
		return nil, !attr
	}
	if !v.IsKnown() {
		n.add(n.unknown, path)
		return nil, true
	}
	ty := v.Type()
	switch {
	case ty == cty.String:
		return v.AsString(), true
	case ty == cty.Bool:
		return v.True(), true
	case ty == cty.Number:
		num, ok := normalizeNumber(v.AsBigFloat())
		if !ok {
			n.add(n.unknown, path)
		}
		return num, true
	case ty.IsSetType():
		// Elements of a set have no stable index, so a set with any unknown part is unknown.
		if !v.IsWhollyKnown() {
			n.add(n.unknown, path)
			return nil, true
		}
		fallthrough
	case ty.IsListType() || ty.IsTupleType():
		list := make([]any, 0, v.LengthInt())
		for _, e := range v.Elements() {
			item, _ := n.value(append(slices.Clip(path), model.IndexStep(len(list))), e, false)
			list = append(list, item)
		}
		return list, true
	case ty.IsMapType() || ty.IsObjectType():
		obj := make(map[string]any, v.LengthInt())
		for k, e := range v.AsValueMap() {
			if item, keep := n.value(append(slices.Clip(path), model.AttrStep(k)), e, ty.IsObjectType()); keep {
				obj[k] = item
			}
		}
		return obj, true
	default:
		// A capsule or other type has no JSON form.
		n.add(n.unknown, path)
		return nil, true
	}
}

// normalizeNumber converts a number by ADR 0004's rule (numbers decode as float64): an integer
// that fits in int64 stays exact, any other number is rounded to float64. ok is false for a
// number outside float64's range, or one that is not zero but rounds to zero, which the caller
// reports as unknown rather than as a different number. Rounding never formats the number in
// decimal, so it costs time linear in the number's precision (ADR 0045).
func normalizeNumber(f *big.Float) (num any, ok bool) {
	if f.IsInt() {
		if i, acc := f.Int64(); acc == big.Exact {
			return i, true
		}
	}
	x, _ := f.Float64()
	if math.IsInf(x, 0) || x == 0 && f.Sign() != 0 {
		return nil, false
	}
	if x == 0 {
		x = 0 // never -0
	}
	return x, true
}

// modelPath converts p, a path into a value of type ty, into a model path, following ty to tell
// a map key from a set element: a path that steps into a set stops at the set, and a step that
// does not match the type stops there too, so the result always covers what p addressed.
func modelPath(ty cty.Type, p cty.Path) model.Path {
	out := model.Path{}
	for _, step := range p {
		switch s := step.(type) {
		case cty.GetAttrStep:
			if !ty.IsObjectType() || !ty.HasAttribute(s.Name) {
				return truncated(out)
			}
			out, ty = append(out, model.AttrStep(s.Name)), ty.AttributeType(s.Name)
		case cty.IndexStep:
			switch {
			case ty.IsObjectType() && s.Key.Type() == cty.String && s.Key.IsKnown() && ty.HasAttribute(s.Key.AsString()):
				name := s.Key.AsString()
				out, ty = append(out, model.AttrStep(name)), ty.AttributeType(name)
			case ty.IsMapType() && s.Key.Type() == cty.String && s.Key.IsKnown():
				out, ty = append(out, model.AttrStep(s.Key.AsString())), ty.ElementType()
			case (ty.IsListType() || ty.IsTupleType()) && s.Key.Type() == cty.Number && s.Key.IsKnown():
				i, acc := s.Key.AsBigFloat().Int64()
				if acc != big.Exact || i < 0 || i > math.MaxInt32 {
					return truncated(out)
				}
				out = append(out, model.IndexStep(int(i)))
				switch {
				case ty.IsListType():
					ty = ty.ElementType()
				case int(i) < len(ty.TupleElementTypes()):
					ty = ty.TupleElementType(int(i))
				default:
					return out
				}
			default:
				return truncated(out)
			}
		default:
			return truncated(out)
		}
	}
	return truncated(out)
}

// truncated returns p, or nil for an empty path, which no model path can express (the schema
// requires a step): the whole value is then reported by NormalizeResource's complete result.
func truncated(p model.Path) model.Path {
	if len(p) == 0 {
		return nil
	}
	return p
}

// outermost returns the paths of set that no other path in set is a prefix of, sorted.
func outermost(set map[string]model.Path) []model.Path {
	paths := slices.SortedFunc(maps.Values(set), compareModelPaths)
	out := make([]model.Path, 0, len(paths))
	for _, p := range paths {
		if len(out) > 0 && modelPathHasPrefix(p, out[len(out)-1]) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// compareModelPaths orders paths step by step, an index before a name, so a prefix sorts directly
// before the paths it covers.
func compareModelPaths(a, b model.Path) int {
	for i := range min(len(a), len(b)) {
		if c := compareModelSteps(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a), len(b))
}

func compareModelSteps(a, b model.PathStep) int {
	switch {
	case a.IsIndex() && b.IsIndex():
		return cmp.Compare(a.Index(), b.Index())
	case a.IsIndex():
		return -1
	case b.IsIndex():
		return 1
	}
	return cmp.Compare(a.Name(), b.Name())
}

func modelPathHasPrefix(p, prefix model.Path) bool {
	return len(prefix) <= len(p) && compareModelPaths(p[:len(prefix)], prefix) == 0
}

// pathKey identifies a path in a set: names and indexes are tagged so "0" and 0 differ.
func pathKey(p model.Path) string {
	var b []byte
	for _, s := range p {
		if s.IsIndex() {
			b = append(b, 'i')
		} else {
			b = append(b, 'n')
		}
		b = append(b, s.String()...)
		b = append(b, 0)
	}
	return string(b)
}

// clearPath sets the value at p in values to nil, if every step before the last exists; a last
// name step adds the attribute to its object if it is missing (a known null that was omitted).
func clearPath(values model.Values, p model.Path) {
	var cur any = map[string]any(values)
	for i, s := range p {
		last := i == len(p)-1
		switch c := cur.(type) {
		case map[string]any:
			if s.IsIndex() {
				return
			}
			if last {
				c[s.Name()] = nil
				return
			}
			if _, ok := c[s.Name()]; !ok {
				return
			}
			cur = c[s.Name()]
		case []any:
			if !s.IsIndex() || s.Index() >= len(c) {
				return
			}
			if last {
				c[s.Index()] = nil
				return
			}
			cur = c[s.Index()]
		default:
			return
		}
	}
}

// modelRange converts an HCL range. Columns are HCL's, which count characters (ADR 0045).
func modelRange(r hcl.Range) model.Range {
	return model.Range{
		StartLine: r.Start.Line, StartColumn: r.Start.Column,
		EndLine: r.End.Line, EndColumn: r.End.Column,
	}
}
