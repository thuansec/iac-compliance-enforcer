package terraform

import (
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// overriddenBody is a resource body with the bodies of its overrides, in the order they apply
// (ADR 0019). At the top of the body, a layer's attribute replaces the attribute of the same
// name, and its nested blocks of a type, static or dynamic, replace all the blocks of that type
// before it. Meta-arguments apply layer by layer: count, for_each, provider, depends_on and each
// lifecycle argument replace the one before.
type overriddenBody struct {
	layers []resourceBody
	// last maps each top-level name to the last layer that sets it: a layer skips the names a
	// later layer sets, so a replaced value is never evaluated, recorded or referenced.
	last map[string]int
}

func newOverriddenBody(layers []resourceBody) *overriddenBody {
	b := &overriddenBody{layers: layers, last: map[string]int{}}
	for i, l := range layers {
		for _, name := range topNames(l) {
			b.last[name] = i
		}
	}
	return b
}

func (b *overriddenBody) metaArguments(d *resourceDecoder, r *Resource) {
	for i, l := range b.layers {
		// As in Terraform, a later non-empty ignore_changes list replaces the one before, and
		// ignore_changes = all, once set, stays.
		all := slices.Equal(r.Lifecycle.IgnoreChanges, []string{"*"})
		if i > 0 && replacesIgnoreChanges(l) {
			r.Lifecycle.IgnoreChanges = nil
		}
		l.metaArguments(d, r)
		if all {
			r.Lifecycle.IgnoreChanges = []string{"*"}
		}
	}
}

func (b *overriddenBody) cost() int {
	n := 0
	for _, l := range b.layers {
		n += l.cost()
	}
	return n
}

func (b *overriddenBody) structure() int {
	n := 0
	for _, l := range b.layers {
		n += l.structure()
	}
	return n
}

func (b *overriddenBody) decode(d *resourceDecoder, r *Resource) cty.Value {
	merged := map[string]cty.Value{}
	defer func() { d.overridden = nil }()
	for i, l := range b.layers {
		d.overridden = func(name string) bool { return b.last[name] > i }
		for name, v := range l.decode(d, r).AsValueMap() {
			merged[name] = v
		}
	}
	return cty.ObjectVal(merged)
}

// blockName is the type of the blocks a nested block makes: its own, or a dynamic block's label.
func blockName(b *hclsyntax.Block) string {
	if b.Type == "dynamic" && len(b.Labels) == 1 {
		return b.Labels[0]
	}
	return b.Type
}

// topNames lists what a layer sets at the top of the body, other than meta-arguments,
// lifecycle and the apply-time blocks: attribute names, and the types of its nested blocks,
// static or dynamic.
func topNames(l resourceBody) []string {
	var names []string
	switch l := l.(type) {
	case hclResourceBody:
		for name := range l.Attributes {
			if !isMetaArgument(name) {
				names = append(names, name)
			}
		}
		for _, blk := range l.Blocks {
			switch {
			case blk.Type == "lifecycle" || blk.Type == "provisioner" || blk.Type == "connection":
			case blk.Type == "dynamic" && len(blk.Labels) == 1:
				names = append(names, blk.Labels[0])
			default:
				names = append(names, blk.Type)
			}
		}
	case jsonResourceBody:
		for _, a := range l.attrs {
			if !isMetaArgument(a.Name) {
				names = append(names, a.Name)
			}
		}
		for _, blk := range l.dynamic {
			names = append(names, blk.Labels[0])
		}
	}
	return names
}

// replacesIgnoreChanges reports whether a layer's lifecycle sets ignore_changes to a non-empty
// list, which replaces the list before it. A layer with more than one lifecycle block has its
// lifecycle ignored (lifecycles), so it replaces nothing.
func replacesIgnoreChanges(l resourceBody) bool {
	var lifecycles []hcl.Body
	switch l := l.(type) {
	case hclResourceBody:
		for _, blk := range l.Blocks {
			if blk.Type == "lifecycle" {
				lifecycles = append(lifecycles, blk.Body)
			}
		}
	case jsonResourceBody:
		for _, blk := range l.lifecycle {
			lifecycles = append(lifecycles, blk.Body)
		}
	}
	if len(lifecycles) != 1 {
		return false
	}
	var expr hcl.Expression
	if syntax, ok := lifecycles[0].(*hclsyntax.Body); ok {
		if a, ok := syntax.Attributes["ignore_changes"]; ok {
			expr = a.Expr
		}
	} else if attrs, _ := lifecycles[0].JustAttributes(); attrs["ignore_changes"] != nil {
		expr = attrs["ignore_changes"].Expr
	}
	if expr == nil || hcl.ExprAsKeyword(expr) == "all" {
		return false
	}
	exprs, diags := hcl.ExprList(expr)
	return !diags.HasErrors() && len(exprs) > 0
}
