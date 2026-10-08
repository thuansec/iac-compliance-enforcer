package terraform

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// jsonResourceSchema lists the blocks of a resource body in JSON syntax that are decoded as
// blocks; every other property is an attribute (ADR 0006).
var jsonResourceSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "lifecycle"},
		{Type: "provisioner", LabelNames: []string{"type"}},
		{Type: "connection"},
		{Type: "dynamic", LabelNames: []string{"type"}},
	},
}

// jsonResourceBody is a resource body in JSON syntax. Without a provider schema a JSON object
// may be a nested block or a map attribute, so every property other than the meta-argument
// blocks is decoded as an attribute and keeps the shape it is written in: a nested block written
// as one object is an object, written as an array it is an array of objects (ADR 0006).
type jsonResourceBody struct {
	attrs     []*hcl.Attribute // in source order, meta-arguments included
	lifecycle []*hcl.Block
	dynamic   []*hcl.Block
}

// jsonResourceBody reads the body of b, a resource in JSON syntax. ok is false when the body
// does not have the shape Terraform accepts, which has been reported.
func (d *resourceDecoder) jsonResourceBody(b Block) (jsonResourceBody, bool) {
	invalid := func(diags hcl.Diagnostics) (jsonResourceBody, bool) {
		rng := b.DefRange
		if diags[0].Subject != nil {
			rng = *diags[0].Subject
		}
		// hcl's Summary only: its Detail can quote values.
		d.m.diag(SeverityWarning, DiagEvaluation, diags[0].Summary,
			"Terraform would reject this resource in JSON syntax, so iace treats its values as unknown.",
			rng.Filename, rng.Start.Line, rng.Start.Column)
		return jsonResourceBody{}, false
	}
	content, remain, diags := b.Body.PartialContent(jsonResourceSchema)
	if diags.HasErrors() {
		return invalid(diags)
	}
	attrs, diags := remain.JustAttributes()
	if diags.HasErrors() {
		return invalid(diags)
	}
	jb := jsonResourceBody{attrs: sortedAttributes(attrs)}
	for _, blk := range content.Blocks {
		switch blk.Type {
		case "lifecycle":
			jb.lifecycle = append(jb.lifecycle, blk)
		case "dynamic":
			jb.dynamic = append(jb.dynamic, blk)
		}
	}
	return jb, true
}

func (b jsonResourceBody) metaArguments(d *resourceDecoder, r *Resource) {
	for _, a := range b.attrs {
		d.meta(a.Name, a.Expr, r)
	}
	d.lifecycles(b.lifecycle, r)
	for _, blk := range b.dynamic {
		d.m.diag(SeverityWarning, DiagJSONDynamicNotExpanded, "Dynamic block in JSON syntax not expanded",
			"iace does not expand dynamic blocks written in JSON syntax yet, so the nested blocks of this type are unknown.",
			blk.DefRange.Filename, blk.DefRange.Start.Line, blk.DefRange.Start.Column)
	}
}

// cost is instanceCost for a JSON body: one, plus the bytes of its attributes other than
// meta-arguments.
func (b jsonResourceBody) cost() int {
	n := 1
	for _, a := range b.attrs {
		if !isMetaArgument(a.Name) {
			n += a.Range.End.Byte - a.Range.Start.Byte
		}
	}
	return n
}

// structure is instanceStructure for a JSON body: nested blocks are attribute values here,
// measured with the values.
func (b jsonResourceBody) structure() int {
	return instanceOverhead + attributeOverhead*(len(b.attrs)+len(b.dynamic))
}

// decode evaluates the attributes of one instance. A dynamic block is not expanded yet
// (T-0106e): its type is unknown (reported once, by metaArguments). An attribute whose value
// holds a "dynamic" key with an object or array, a dynamic block inside a nested block, is
// unknown too, with a warning: as data it would hide the blocks it generates. A map argument
// with such a key is also unknown, which fails closed.
func (b jsonResourceBody) decode(d *resourceDecoder, r *Resource) cty.Value {
	attrs := map[string]cty.Value{}
	for _, a := range b.attrs {
		if isMetaArgument(a.Name) {
			continue
		}
		r.Attributes[a.Name] = a.Expr.Range()
		v, _ := d.evalBounded(a.Expr, a.Name, a.NameRange)
		if holdsDynamicBlock(v) {
			d.m.diag(SeverityWarning, DiagJSONDynamicNotExpanded, "Dynamic block in JSON syntax not expanded",
				"This value holds a dynamic block, which iace does not expand in JSON syntax yet, so the value is unknown.",
				a.NameRange.Filename, a.NameRange.Start.Line, a.NameRange.Start.Column)
			sensitive := v.ContainsMarked()
			v = cty.DynamicVal
			if sensitive {
				v = v.Mark(SensitiveMark) // fail closed
			}
		}
		attrs[a.Name] = v
	}
	for _, blk := range b.dynamic {
		attrs[blk.Labels[0]] = cty.DynamicVal
	}
	return cty.ObjectVal(attrs)
}

// holdsDynamicBlock reports whether v holds an object or map with a "dynamic" key whose value is
// an object, a map, a tuple, a list or unknown. v has been measured, which bounds the walk.
func holdsDynamicBlock(v cty.Value) bool {
	stack := []cty.Value{v}
	for len(stack) > 0 {
		val, _ := stack[len(stack)-1].Unmark() // shallow: each child is unmarked when popped
		stack = stack[:len(stack)-1]
		if !val.IsKnown() || val.IsNull() {
			continue
		}
		ty := val.Type()
		if !ty.IsObjectType() && !ty.IsMapType() && !ty.IsTupleType() && !ty.IsListType() && !ty.IsSetType() {
			continue
		}
		dyn, has := cty.NilVal, false
		switch {
		case ty.IsObjectType() && ty.HasAttribute("dynamic"):
			dyn, has = val.GetAttr("dynamic"), true
		case ty.IsMapType() && val.HasIndex(cty.StringVal("dynamic")).True():
			dyn, has = val.Index(cty.StringVal("dynamic")), true
		}
		if has {
			dyn, _ = dyn.Unmark()
			dt := dyn.Type()
			if !dyn.IsKnown() || dt.IsObjectType() || dt.IsMapType() || dt.IsTupleType() || dt.IsListType() {
				return true
			}
		}
		for it := val.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			stack = append(stack, ev)
		}
	}
	return false
}
