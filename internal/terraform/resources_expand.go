package terraform

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// expand returns the instances of r: one without a key when it has neither count nor
// for_each, one per count index or for_each key (sorted, at most maxInstancesPerResource), or a
// placeholder when the expansion is unknown or invalid, which sets CountUnknown or
// ForEachUnknown on r.
func (d *resourceDecoder) expand(r *Resource) []instanceSpec {
	switch {
	case r.Count != nil && r.ForEach != nil:
		d.expansionDiag(DiagInvalidExpansion, r.Count, "Invalid count and for_each",
			"Terraform rejects a resource or module call that sets both count and for_each, so iace checks one placeholder instance with unknown values for them.")
		r.CountUnknown, r.ForEachUnknown = true, true
		return []instanceSpec{placeholder()}
	case r.Count != nil:
		return d.expandCount(r)
	case r.ForEach != nil:
		return d.expandForEach(r)
	}
	return []instanceSpec{{}}
}

// expandCount expands r by its count.
func (d *resourceDecoder) expandCount(r *Resource) []instanceSpec {
	v, ok := d.evalBounded(r.Count, "count", r.Count.Range())
	invalid := func(why string) []instanceSpec {
		r.CountUnknown = true
		if ok {
			d.expansionDiag(DiagInvalidExpansion, r.Count, "Invalid count",
				"Terraform rejects this count ("+why+"), so iace checks one placeholder instance with an unknown count.index.")
		}
		return []instanceSpec{placeholder()}
	}
	// Terraform allows a sensitive count; the indexes it produces are not sensitive.
	v, _ = v.UnmarkDeep()
	switch {
	case !ok:
		return invalid("") // already reported
	case !v.IsWhollyKnown():
		r.CountUnknown = true
		d.expansionDiag(DiagUnknownExpansion, r.Count, "Unknown count",
			"The count is not known statically, so iace checks one placeholder instance with an unknown count.index.")
		return []instanceSpec{placeholder()}
	case v.IsNull():
		return invalid("it is null")
	}
	n, err := convert.Convert(v, cty.Number)
	if err != nil {
		return invalid("it is not a number")
	}
	f := n.AsBigFloat()
	if !f.IsInt() || f.Sign() < 0 {
		return invalid("it is not a whole number of zero or more")
	}
	count := maxInstancesPerResource + 1
	if i, acc := f.Int64(); acc == big.Exact {
		count = int(min(i, int64(count)))
	}
	if count > maxInstancesPerResource {
		count = maxInstancesPerResource
		d.instanceLimit(r.Count)
	}
	specs := make([]instanceSpec, count)
	for i := range specs {
		specs[i] = instanceSpec{
			key:    model.IntKey(i),
			suffix: "[" + strconv.Itoa(i) + "]",
			vars:   map[string]cty.Value{"count": cty.ObjectVal(map[string]cty.Value{"index": cty.NumberIntVal(int64(i))})},
		}
	}
	return specs
}

// expandForEach expands r by its for_each: a map or object (each.value is the element) or a
// set of strings (each.value is the key).
func (d *resourceDecoder) expandForEach(r *Resource) []instanceSpec {
	v, ok := d.evalBounded(r.ForEach, "for_each", r.ForEach.Range())
	invalid := func(why string) []instanceSpec {
		r.ForEachUnknown = true
		if ok {
			d.expansionDiag(DiagInvalidExpansion, r.ForEach, "Invalid for_each",
				"Terraform rejects this for_each ("+why+"), so iace checks one placeholder instance with an unknown each.")
		}
		return []instanceSpec{placeholder()}
	}
	unknown := func() []instanceSpec {
		r.ForEachUnknown = true
		d.expansionDiag(DiagUnknownExpansion, r.ForEach, "Unknown for_each",
			"The for_each keys are not known statically, so iace checks one placeholder instance with an unknown each.")
		return []instanceSpec{placeholder()}
	}
	ty := v.Type()
	switch {
	case !ok:
		return invalid("") // already reported
	case v.IsMarked():
		// A set's elements are its keys, and cty marks a set by its elements' marks.
		return invalid("it is sensitive")
	case !v.IsKnown():
		return unknown()
	case v.IsNull():
		return invalid("it is null")
	case ty.IsSetType() && !v.IsWhollyKnown():
		return unknown()
	case ty.IsSetType() && v.LengthInt() > 0 && !ty.ElementType().Equals(cty.String):
		return invalid("a set must hold strings")
	case !ty.IsSetType() && !ty.IsMapType() && !ty.IsObjectType():
		return invalid("it must be a map, an object or a set of strings")
	}
	var specs []instanceSpec
	for it := v.ElementIterator(); it.Next(); {
		if len(specs) == maxInstancesPerResource {
			d.instanceLimit(r.ForEach)
			break
		}
		k, ev := it.Element()
		if k.IsNull() {
			return invalid("a set must not hold null")
		}
		key := k.AsString() // a set's element is both its key and its value
		specs = append(specs, instanceSpec{
			key:    model.StringKey(key),
			suffix: "[" + quoteKey(key) + "]",
			vars:   map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{"key": cty.StringVal(key), "value": ev})},
		})
	}
	return specs
}

// quoteKey quotes a for_each key as Terraform writes it in an address: an HCL string, with
// "${" and "%{" escaped and control characters as \uXXXX.
func quoteKey(key string) string {
	return string(hclwrite.TokensForValue(cty.StringVal(key)).Bytes())
}

// placeholder is the instance of an unknown or invalid expansion.
func placeholder() instanceSpec {
	return instanceSpec{
		suffix: "[*]",
		vars: map[string]cty.Value{
			"count": cty.ObjectVal(map[string]cty.Value{"index": cty.UnknownVal(cty.Number)}),
			"each":  cty.ObjectVal(map[string]cty.Value{"key": cty.UnknownVal(cty.String), "value": cty.DynamicVal}),
		},
	}
}

// setInstance makes vars (count or each) the values of the instance being decoded. Each value
// is measured once per instance, so references cost lookups.
func (d *resourceDecoder) setInstance(vars map[string]cty.Value) {
	d.inst, d.instSizes, d.instSensitive = vars, map[string]int{}, map[string]bool{}
	for name, v := range vars {
		n, ok := valueSize(v, maxLocalValueSize, maxNesting)
		if !ok {
			n = maxLocalValueSize + 1
		}
		d.instSizes[name], d.instSensitive[name] = n, v.ContainsMarked()
	}
}

// instanceLimit reports a resource or module call with more than maxInstancesPerResource
// instances.
func (d *resourceDecoder) instanceLimit(expr hcl.Expression) {
	d.instancesLimited = true
	d.expansionDiag(DiagExpansionLimit, expr, "Too many instances",
		fmt.Sprintf("The resource or module call has more than %d instances; iace checks the first %d.", maxInstancesPerResource, maxInstancesPerResource))
}

// moduleLimit reports a resource whose instances are cut short by maxInstancesPerModule,
// maxInstanceStructure or maxExpansionWork: each such resource is reported.
func (d *resourceDecoder) moduleLimit(r *Resource) {
	at := r.DefRange
	switch {
	case r.Count != nil:
		at = r.Count.Range()
	case r.ForEach != nil:
		at = r.ForEach.Range()
	}
	d.m.diag(SeverityWarning, DiagExpansionLimit, "Too many instances in the module",
		"The module's resource instances pass the limit for a module (instances, their size, or the source evaluated again per instance), so the rest of this resource's instances are not checked.",
		at.Filename, at.Start.Line, at.Start.Column)
}

// expansionDiag reports a warning at expr, without quoting its value.
func (d *resourceDecoder) expansionDiag(code DiagCode, expr hcl.Expression, summary, detail string) {
	r := expr.Range()
	d.m.diag(SeverityWarning, code, summary, detail, r.Filename, r.Start.Line, r.Start.Column)
}
