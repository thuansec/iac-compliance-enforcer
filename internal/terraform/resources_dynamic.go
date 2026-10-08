package terraform

import (
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// iterator is a dynamic block's iterator in scope: its object (key and value), measured once.
type iterator struct {
	val       cty.Value
	size      int
	sensitive bool
}

// dynamic expands a dynamic block into entries of its type, appended to blocks in source
// order, as hcl's dynblock extension does for Terraform. Its iterator (named by iterator, or
// else the block label) holds each element's key and value: an index for a list or tuple, a key
// for a map or object, and the element itself for a set. A sensitive for_each marks the entries.
// An unknown for_each is one entry evaluated with an unknown iterator, and the type's path is
// unknown; so is a dynamic block cut short by a limit. An invalid one makes its type unknown:
// no single label, a meta-argument block type at the top of a resource, no for_each, an
// argument or block other than for_each, iterator, labels and one content block without
// labels, or a for_each that is null or not a collection. Each case warns.
func (d *resourceDecoder) dynamic(b *hclsyntax.Block, prefix string, path cty.Path, r *Resource,
	blocks map[string][]cty.Value, unknown map[string]bool, top bool,
) {
	invalidAt := func(rng hcl.Range, name, why string) {
		if name != "" {
			unknown[name] = true
		}
		d.m.diag(SeverityWarning, DiagInvalidExpansion, "Invalid dynamic block",
			"Terraform rejects this dynamic block ("+why+"), so iace treats the blocks of its type as unknown.",
			rng.Filename, rng.Start.Line, rng.Start.Column)
	}
	if len(b.Labels) != 1 {
		invalidAt(b.TypeRange, "", "it needs exactly one label, the block type")
		return
	}
	name := b.Labels[0]
	var content []*hclsyntax.Block
	for _, c := range b.Body.Blocks {
		if c.Type != "content" || len(c.Labels) > 0 {
			invalidAt(c.TypeRange, name, "it may only hold one content block, without labels")
			return
		}
		content = append(content, c)
	}
	for _, a := range sortedSyntaxAttributes(b.Body.Attributes) {
		if a.Name != "for_each" && a.Name != "iterator" && a.Name != "labels" {
			invalidAt(a.NameRange, name, "it may only set for_each, iterator and labels")
			return
		}
	}
	forEach := b.Body.Attributes["for_each"]
	switch {
	case top && (name == "lifecycle" || name == "provisioner" || name == "connection"):
		invalidAt(b.TypeRange, name, "a meta-argument block cannot be dynamic")
		return
	case forEach == nil:
		invalidAt(b.TypeRange, name, "for_each is missing")
		return
	case len(content) != 1:
		invalidAt(b.TypeRange, name, "it needs exactly one content block")
		return
	}
	iterName := name
	if it := b.Body.Attributes["iterator"]; it != nil {
		tr, diags := hcl.AbsTraversalForExpr(it.Expr)
		if diags.HasErrors() || len(tr) != 1 {
			invalidAt(it.Expr.Range(), name, "iterator must be a name")
			return
		}
		iterName = tr.RootName()
	}
	v, ok := d.evalBounded(forEach.Expr, "for_each", forEach.NameRange)
	if !ok {
		unknown[name] = true // already reported
		return
	}
	v, marks := v.Unmark()
	body := content[0].Body
	entry := func(key, val cty.Value) {
		saved, had := d.iters[iterName]
		it := cty.ObjectVal(map[string]cty.Value{"key": key, "value": val})
		size, fits := valueSize(it, maxLocalValueSize, maxNesting)
		if !fits {
			size = maxLocalValueSize + 1
		}
		if d.iters == nil {
			d.iters = map[string]iterator{}
		}
		d.iters[iterName] = iterator{val: it, size: size, sensitive: it.ContainsMarked() || len(marks) > 0}
		e := d.nested(name, body, prefix, path, len(blocks[name]), r)
		if had {
			d.iters[iterName] = saved
		} else {
			delete(d.iters, iterName)
		}
		blocks[name] = append(blocks[name], e.WithMarks(marks))
	}
	typePath := append(slices.Clip(path), cty.GetAttrStep{Name: name})
	rng := forEach.Expr.Range()
	ty := v.Type()
	switch {
	case !v.IsKnown() || ty.IsSetType() && !v.IsWhollyKnown():
		d.m.diag(SeverityWarning, DiagUnknownExpansion, "Unknown dynamic block for_each",
			"The for_each of this dynamic block is not known statically, so iace checks one entry with an unknown iterator and treats the number of entries as unknown.",
			rng.Filename, rng.Start.Line, rng.Start.Column)
		d.extraUnknown = append(d.extraUnknown, typePath)
		entry(cty.DynamicVal, cty.DynamicVal)
		return
	case v.IsNull():
		invalidAt(rng, name, "for_each is null")
		return
	case !v.CanIterateElements():
		invalidAt(rng, name, "for_each must be a collection")
		return
	}
	cost := instanceCost(body)
	structure := blockOverhead + instanceStructure(body) - instanceOverhead
	n := 0
	for it := v.ElementIterator(); it.Next(); n++ {
		limit := n == maxInstancesPerResource ||
			d.structure+structure > maxInstanceStructure ||
			n > 0 && d.expansionWork+cost > maxExpansionWork
		if limit {
			d.m.diag(SeverityWarning, DiagExpansionLimit, "Too many dynamic blocks",
				"This dynamic block passes the limit for entries (per block, or the module's instances, their size or the source evaluated again), so iace checks the entries before it and treats the number of entries as unknown.",
				rng.Filename, rng.Start.Line, rng.Start.Column)
			d.extraUnknown = append(d.extraUnknown, typePath)
			return
		}
		if n > 0 {
			d.expansionWork += cost
		}
		d.structure += structure
		entry(it.Element())
	}
}

// mergeUnknown adds extra to the outermost unknown paths in base, keeping only outermost
// paths, in value order.
func mergeUnknown(base, extra []cty.Path) []cty.Path {
	if len(extra) == 0 {
		return base
	}
	all := append(slices.Clip(base), extra...)
	slices.SortFunc(all, comparePath)
	var out []cty.Path
	for _, p := range all {
		if len(out) > 0 && hasPrefix(p, out[len(out)-1]) {
			continue // covered by an unknown ancestor (or a duplicate)
		}
		out = append(out, p)
	}
	return out
}

// comparePath orders paths as their values are ordered: attributes by name, indexes by
// number, and a path before its descendants.
func comparePath(a, b cty.Path) int {
	for i := range min(len(a), len(b)) {
		if c := compareStep(a[i], b[i]); c != 0 {
			return c
		}
	}
	return len(a) - len(b)
}

func compareStep(a, b cty.PathStep) int {
	ak, bk := stepKey(a), stepKey(b)
	switch {
	case ak.Type() == cty.Number && bk.Type() == cty.Number:
		return ak.AsBigFloat().Cmp(bk.AsBigFloat())
	case ak.Type() == cty.String && bk.Type() == cty.String:
		switch as, bs := ak.AsString(), bk.AsString(); {
		case as < bs:
			return -1
		case as > bs:
			return 1
		}
		return 0
	case ak.Type() == cty.Number:
		return -1
	}
	return 1
}

// stepKey is a path step's attribute name or index key.
func stepKey(s cty.PathStep) cty.Value {
	switch s := s.(type) {
	case cty.GetAttrStep:
		return cty.StringVal(s.Name)
	case cty.IndexStep:
		if s.Key.IsKnown() && !s.Key.IsNull() {
			return s.Key
		}
	}
	return cty.StringVal("")
}

// hasPrefix reports whether p starts with prefix.
func hasPrefix(p, prefix cty.Path) bool {
	if len(prefix) > len(p) {
		return false
	}
	for i := range prefix {
		if compareStep(p[i], prefix[i]) != 0 {
			return false
		}
	}
	return true
}
