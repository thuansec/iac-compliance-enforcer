package terraform

import (
	"fmt"
	"slices"

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

// jsonNestedSchema lists the blocks of a nested or content body in JSON syntax.
var jsonNestedSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{{Type: "dynamic", LabelNames: []string{"type"}}},
}

// jsonDynamicSchema is the content of a dynamic block in JSON syntax, as hcl's dynblock reads it.
var jsonDynamicSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "for_each"}, {Name: "iterator"}, {Name: "labels"}},
	Blocks:     []hcl.BlockHeaderSchema{{Type: "content"}},
}

// jsonBody is a body in JSON syntax: the resource's own body, or a nested or content body.
// Without a provider schema a JSON object may be a nested block or a map attribute, so every
// property other than the blocks in its schema is decoded as an attribute and keeps the shape it
// is written in (ADR 0006). The exception is a property that holds a dynamic block in its
// source, or shares a dynamic block's type: it can only be a nested block, so it is decoded as
// blocks, an array (ADR 0007).
type jsonBody struct {
	body      hcl.Body
	attrs     []*hcl.Attribute // in source order, meta-arguments included at the top
	lifecycle []*hcl.Block
	dynamic   []*hcl.Block
	// dynamicBytes is the source size of the dynamic blocks, each measured from its "dynamic"
	// key to its closing brace (a block's DefRange is only its opening brace). Blocks under one
	// key overlap, which only over-charges.
	dynamicBytes int
}

// parseJSONBody reads body with the resource schema (top) or the nested one.
func parseJSONBody(body hcl.Body, top bool) (jsonBody, hcl.Diagnostics) {
	schema := jsonNestedSchema
	if top {
		schema = jsonResourceSchema
	}
	content, remain, diags := body.PartialContent(schema)
	if diags.HasErrors() {
		return jsonBody{}, diags
	}
	attrs, diags := remain.JustAttributes()
	if diags.HasErrors() {
		return jsonBody{}, diags
	}
	jb := jsonBody{body: body, attrs: sortedAttributes(attrs)}
	for _, blk := range content.Blocks {
		switch blk.Type {
		case "lifecycle":
			jb.lifecycle = append(jb.lifecycle, blk)
		case "dynamic":
			jb.dynamic = append(jb.dynamic, blk)
			start, end := blk.TypeRange.Start.Byte, blk.Body.MissingItemRange().End.Byte
			jb.dynamicBytes += max(end-start, blk.DefRange.End.Byte-blk.DefRange.Start.Byte)
		}
	}
	return jb, nil
}

// jsonResourceBody is the body of a resource in JSON syntax.
type jsonResourceBody struct{ jsonBody }

// jsonResourceBody reads the body of b, a resource in JSON syntax. ok is false when the body
// does not have the shape Terraform accepts, which has been reported.
func (d *resourceDecoder) jsonResourceBody(b Block) (jsonResourceBody, bool) {
	jb, diags := parseJSONBody(b.Body, true)
	if diags.HasErrors() {
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
	return jsonResourceBody{jb}, true
}

func (b jsonResourceBody) metaArguments(d *resourceDecoder, r *Resource) {
	for _, a := range b.attrs {
		d.meta(a.Name, a.Expr, r)
	}
	d.lifecycles(b.lifecycle, r)
}

func (b jsonResourceBody) cost() int      { return b.jsonBody.cost(true) }
func (b jsonResourceBody) structure() int { return b.jsonBody.structure() }
func (b jsonResourceBody) decode(d *resourceDecoder, r *Resource) cty.Value {
	return d.jsonValue(b.jsonBody, "", nil, r, true)
}

// jsonEvalFactor weighs JSON source in instanceCost: every evaluation of a JSON string parses
// it as a template again (once to inspect it, once to evaluate it), so a byte of JSON costs
// about four times a byte of HCL, whose syntax tree is parsed once (TestJSONDynamicChargesItsSource:
// 1.7µs per JSON byte).
const jsonEvalFactor = 4

// cost is instanceCost for a JSON body: one, plus jsonEvalFactor times the bytes of its
// attributes (other than meta-arguments at the top) and of its dynamic blocks.
func (b jsonBody) cost(top bool) int {
	n := b.dynamicBytes
	for _, a := range b.attrs {
		if !top || !isMetaArgument(a.Name) {
			n += a.Range.End.Byte - a.Range.Start.Byte
		}
	}
	return 1 + jsonEvalFactor*n
}

// structure is instanceStructure for a JSON body: nested values are measured with the values.
func (b jsonBody) structure() int {
	return instanceOverhead + attributeOverhead*len(b.attrs) + blockOverhead*len(b.dynamic)
}

// jsonValue decodes a JSON body into an object, as body does for HCL. prefix and path are the
// body's dot-joined path and cty path; top is true for the resource's own body. Recursion
// follows the JSON nesting, which the nesting guard bounds.
func (d *resourceDecoder) jsonValue(jb jsonBody, prefix string, path cty.Path, r *Resource, top bool) cty.Value {
	attrs := map[string]cty.Value{}
	blocks := map[string][]cty.Value{}
	unknown := map[string]bool{}
	dynamicTypes := map[string]bool{}
	for _, blk := range jb.dynamic {
		dynamicTypes[blk.Labels[0]] = true
	}
	// Nested blocks, static and dynamic, are merged in source order, as hcl's dynblock does.
	type blockItem struct {
		offset int
		attr   *hcl.Attribute
		dyn    *hcl.Block
	}
	var items []blockItem
	for _, a := range jb.attrs {
		if top && isMetaArgument(a.Name) {
			continue
		}
		if dynamicTypes[a.Name] || d.holdsDynamicSource(a.Expr) {
			items = append(items, blockItem{offset: a.Range.Start.Byte, attr: a})
			continue
		}
		r.Attributes[prefix+a.Name] = a.Expr.Range()
		attrs[a.Name], _ = d.evalBounded(a.Expr, a.Name, a.NameRange)
	}
	for _, blk := range jb.dynamic {
		items = append(items, blockItem{offset: blk.DefRange.Start.Byte, dyn: blk})
	}
	slices.SortStableFunc(items, func(x, y blockItem) int { return x.offset - y.offset })
	for _, it := range items {
		if it.attr != nil {
			d.jsonBlocks(jb, it.attr, prefix, path, r, blocks, unknown)
			continue
		}
		d.jsonDynamic(it.dyn, prefix, path, r, blocks, unknown, top)
	}
	for name, list := range blocks {
		attrs[name] = cty.TupleVal(list)
	}
	for name := range unknown {
		attrs[name] = cty.DynamicVal
	}
	return cty.ObjectVal(attrs)
}

// jsonBlocks decodes the property a of jb as nested blocks (an object is one block, an array of
// objects one per element) and appends them to blocks. A value that is neither makes the type
// unknown with a warning: it holds a dynamic block, so it cannot be an attribute.
func (d *resourceDecoder) jsonBlocks(jb jsonBody, a *hcl.Attribute, prefix string, path cty.Path, r *Resource,
	blocks map[string][]cty.Value, unknown map[string]bool,
) {
	content, _, diags := jb.body.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: a.Name}}})
	if diags.HasErrors() {
		d.invalidDynamic(a.NameRange, a.Name, "a value holding a dynamic block must be a nested block: an object or an array of objects", unknown)
		return
	}
	for _, blk := range content.Blocks {
		nb, diags := parseJSONBody(blk.Body, false)
		if diags.HasErrors() {
			d.invalidDynamic(blk.DefRange, a.Name, "a nested block must be an object", unknown)
			return
		}
		blocks[a.Name] = append(blocks[a.Name], d.jsonNested(a.Name, nb, prefix, path, len(blocks[a.Name]), r))
	}
}

// jsonNested decodes entry i of the nested blocks of type name.
func (d *resourceDecoder) jsonNested(name string, nb jsonBody, prefix string, path cty.Path, i int, r *Resource) cty.Value {
	p := make(cty.Path, len(path), len(path)+2)
	copy(p, path)
	p = append(p, cty.GetAttrStep{Name: name}, cty.IndexStep{Key: cty.NumberIntVal(int64(i))})
	return d.jsonValue(nb, fmt.Sprintf("%s%s.%d.", prefix, name, i), p, r, false)
}

// jsonDynamic expands a dynamic block in JSON syntax as dynamic does in HCL.
func (d *resourceDecoder) jsonDynamic(blk *hcl.Block, prefix string, path cty.Path, r *Resource,
	blocks map[string][]cty.Value, unknown map[string]bool, top bool,
) {
	name := blk.Labels[0]
	content, diags := blk.Body.Content(jsonDynamicSchema)
	switch {
	case diags.HasErrors():
		rng := blk.DefRange
		if diags[0].Subject != nil {
			rng = *diags[0].Subject
		}
		d.invalidDynamic(rng, name, "it may only set for_each, iterator, labels and one content object", unknown)
		return
	case top && slices.Contains([]string{"lifecycle", "provisioner", "connection"}, name):
		d.invalidDynamic(blk.DefRange, name, "a meta-argument block cannot be dynamic", unknown)
		return
	case content.Attributes["for_each"] == nil:
		d.invalidDynamic(blk.DefRange, name, "for_each is missing", unknown)
		return
	case len(content.Blocks) != 1:
		d.invalidDynamic(blk.DefRange, name, "it needs exactly one content block", unknown)
		return
	}
	nb, diags := parseJSONBody(content.Blocks[0].Body, false)
	if diags.HasErrors() {
		d.invalidDynamic(content.Blocks[0].DefRange, name, "content must be an object", unknown)
		return
	}
	var iter hcl.Expression
	if it := content.Attributes["iterator"]; it != nil {
		iter = it.Expr
	}
	d.expandDynamic(dynamicSpec{
		name:      name,
		forEach:   content.Attributes["for_each"],
		iterator:  iter,
		cost:      nb.cost(false),
		structure: blockOverhead + nb.structure() - instanceOverhead,
		decode: func(i int) cty.Value {
			return d.jsonNested(name, nb, prefix, path, i, r)
		},
	}, path, blocks, unknown)
}

// sourceKey identifies an expression by its source range.
type sourceKey struct {
	file       string
	start, end int
}

// holdsDynamicSource reports whether the JSON value expr holds, at any depth, an object with a
// "dynamic" key whose value is an object or an array: a nested block holding a dynamic block. It
// reads the source without evaluating it, so iterators that are not yet in scope do not matter.
// Results are memoized by source range for every value walked: each nesting level of a block
// asks again about the values below it, which would otherwise cost depth times size. The
// recursion is bounded by the nesting guard.
func (d *resourceDecoder) holdsDynamicSource(expr hcl.Expression) bool {
	r := expr.Range()
	key := sourceKey{r.Filename, r.Start.Byte, r.End.Byte}
	if v, ok := d.dynamicSource[key]; ok {
		return v
	}
	found := false
	if pairs, diags := hcl.ExprMap(expr); !diags.HasErrors() {
		for _, p := range pairs {
			if k, kd := p.Key.Value(nil); !kd.HasErrors() && k.Type() == cty.String && k.IsKnown() && !k.IsNull() && k.AsString() == "dynamic" {
				_, md := hcl.ExprMap(p.Value)
				_, ld := hcl.ExprList(p.Value)
				found = found || !md.HasErrors() || !ld.HasErrors()
			}
			// Walk every child, even after a find, so each is memoized once.
			found = d.holdsDynamicSource(p.Value) || found
		}
	} else if elems, diags := hcl.ExprList(expr); !diags.HasErrors() {
		for _, e := range elems {
			found = d.holdsDynamicSource(e) || found
		}
	}
	if d.dynamicSource == nil {
		d.dynamicSource = map[sourceKey]bool{}
	}
	d.dynamicSource[key] = found
	return found
}
