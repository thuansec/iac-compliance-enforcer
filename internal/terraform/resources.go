package terraform

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// Diagnostic codes for resource decoding.
const (
	// DiagDynamicBlockNotExpanded: a dynamic block is not expanded yet (T-0106c), so the nested
	// blocks of its type are unknown.
	DiagDynamicBlockNotExpanded DiagCode = "dynamic_block_not_expanded"
	// DiagJSONBodyNotDecoded: a resource written in JSON syntax is not decoded yet (T-0106d),
	// so its whole value is unknown.
	DiagJSONBodyNotDecoded DiagCode = "json_body_not_decoded"
)

// maxResourcesSize bounds the attribute values of all of a module's resources together, in
// valueSize units, as maxLocalsSize bounds locals: each value is walked a few times (measured,
// then for its unknown paths), so 2^24 units took about 4s. One attribute is bounded by
// maxLocalValueSize.
const maxResourcesSize = 1 << 22

// Resource is one resource or data source block, decoded without a provider schema. Expanding
// count and for_each into instances is T-0106b; until then each block is one instance.
type Resource struct {
	Mode model.ResourceMode
	Type string
	Name string
	// Address is "type.name" or "data.type.name".
	Address string
	// Value is an object of the block's attributes and nested blocks, each nested block type a
	// tuple of objects in source order. Meta-arguments are not part of it. It is unknown, wholly
	// or in part, where iace cannot evaluate it statically, and keeps SensitiveMark where a
	// value comes from a sensitive variable.
	Value cty.Value
	// Unknown lists the outermost unknown paths in Value, as Local.Unknown.
	Unknown []cty.Path
	// Attributes maps each attribute's dot-joined path ("metadata_options.0.http_tokens") to
	// the range of its expression.
	Attributes map[string]hcl.Range
	// Count and ForEach are the meta-argument expressions, nil when absent.
	Count, ForEach hcl.Expression
	// ProviderConfig is the provider meta-argument ("aws.eu"), "" when absent.
	ProviderConfig string
	// DependsOn holds the addresses in depends_on, sorted and unique.
	DependsOn []string
	Lifecycle model.Lifecycle
	// File is relative to the scan root; Range spans the block and DefRange is its header.
	File            string
	Range, DefRange hcl.Range
}

// resourceDecoder decodes a module's resources within the module's size budget.
type resourceDecoder struct {
	m      *ParsedModule
	vars   cty.Value
	locals map[string]Local
	// sizes and sensitive cache the size of "var.<name>" and "local.<name>", and whether it
	// contains a sensitive value: both walk the whole value, which many references would repeat.
	sizes     map[string]int
	sensitive map[string]bool
	// remaining is what is left of maxResourcesSize; totalWarned records the warning for it.
	remaining   int
	totalWarned bool
}

// DecodeResources decodes the module's resource and data blocks, in block order, evaluating
// their attributes with vars as var.* and locals as local.*. What cannot be evaluated is
// unknown with a warning, never an error; only a cancelled context is an error. Ephemeral
// resources are not decoded: their values are never stored, so no policy inspects them.
func (m *ParsedModule) DecodeResources(ctx context.Context, vars map[string]Variable, locals map[string]Local) ([]Resource, error) {
	d := &resourceDecoder{
		m:         m,
		vars:      variablesObject(vars),
		locals:    locals,
		sizes:     map[string]int{},
		sensitive: map[string]bool{},
		remaining: maxResourcesSize,
	}
	var out []Resource
	for _, b := range m.Blocks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if (b.Type != "resource" && b.Type != "data") || len(b.Labels) != 2 {
			continue
		}
		r := Resource{Type: b.Labels[0], Name: b.Labels[1], File: b.File, Range: b.Range, DefRange: b.DefRange}
		if b.Type == "resource" {
			r.Mode, r.Address = model.ModeManaged, r.Type+"."+r.Name
		} else {
			r.Mode, r.Address = model.ModeData, "data."+r.Type+"."+r.Name
		}
		r.Attributes = map[string]hcl.Range{}
		body, ok := b.Body.(*hclsyntax.Body)
		if !ok {
			m.diag(SeverityWarning, DiagJSONBodyNotDecoded, "Resource in JSON syntax not decoded",
				"iace does not decode resources written in JSON syntax yet, so this resource's values are unknown.",
				b.File, b.DefRange.Start.Line, b.DefRange.Start.Column)
			r.Value = cty.DynamicVal
		} else {
			r.Value = d.body(body, "", &r, true)
		}
		r.Unknown = unknownPaths(r.Value)
		out = append(out, r)
	}
	m.sortDiagnostics()
	return out, nil
}

// body decodes a block body into an object. prefix is the body's dot-joined path, ending in a
// dot unless empty; top is true for the resource's own body, the only place meta-arguments are.
// Recursion follows block nesting, which the nesting guard bounds.
func (d *resourceDecoder) body(body *hclsyntax.Body, prefix string, r *Resource, top bool) cty.Value {
	attrs := map[string]cty.Value{}
	for _, a := range sortedSyntaxAttributes(body.Attributes) {
		if top && d.meta(a, r) {
			continue
		}
		r.Attributes[prefix+a.Name] = a.Expr.Range()
		attrs[a.Name] = d.attribute(a)
	}
	blocks := map[string][]cty.Value{}
	dynamic := map[string]bool{}
	for _, b := range body.Blocks {
		switch {
		case top && b.Type == "lifecycle":
			d.lifecycle(b, r)
			continue
		case top && (b.Type == "provisioner" || b.Type == "connection"):
			continue // run at apply time; no policy input
		case b.Type == "dynamic":
			if len(b.Labels) > 0 {
				dynamic[b.Labels[0]] = true
			}
			d.m.diag(SeverityWarning, DiagDynamicBlockNotExpanded, "Dynamic block not expanded",
				"iace does not expand dynamic blocks yet, so the nested blocks of this type are unknown.",
				r.File, b.TypeRange.Start.Line, b.TypeRange.Start.Column)
			continue
		}
		path := fmt.Sprintf("%s%s.%d.", prefix, b.Type, len(blocks[b.Type]))
		blocks[b.Type] = append(blocks[b.Type], d.body(b.Body, path, r, false))
	}
	for name, list := range blocks {
		if _, clash := attrs[name]; clash {
			attrs[name] = cty.DynamicVal // an attribute and a block of one name: Terraform rejects it
			continue
		}
		attrs[name] = cty.TupleVal(list)
	}
	for name := range dynamic {
		attrs[name] = cty.DynamicVal
	}
	return cty.ObjectVal(attrs)
}

// meta records a in r if it is a meta-argument of the resource body, and reports whether it was.
func (d *resourceDecoder) meta(a *hclsyntax.Attribute, r *Resource) bool {
	switch a.Name {
	case "count":
		r.Count = a.Expr
	case "for_each":
		r.ForEach = a.Expr
	case "provider":
		tr, diags := hcl.AbsTraversalForExpr(a.Expr)
		name, ok := traversalAttr(tr, 1)
		switch {
		case diags.HasErrors() || len(tr) == 0 || len(tr) > 2 || len(tr) == 2 && !ok:
			d.invalid(a.Expr, "Invalid provider reference")
		case ok:
			r.ProviderConfig = tr.RootName() + "." + name
		default:
			r.ProviderConfig = tr.RootName()
		}
	case "depends_on":
		exprs, diags := hcl.ExprList(a.Expr)
		if diags.HasErrors() {
			d.invalid(a.Expr, "Invalid depends_on")
			return true
		}
		for _, e := range exprs {
			tr, diags := hcl.AbsTraversalForExpr(e)
			if diags.HasErrors() || len(tr) == 0 {
				d.invalid(e, "Invalid depends_on reference")
				continue
			}
			addr, ok := referenceAddress(tr)
			if !ok {
				d.invalid(e, "Invalid depends_on reference")
				continue
			}
			r.DependsOn = append(r.DependsOn, addr)
		}
		slices.Sort(r.DependsOn)
		r.DependsOn = slices.Compact(r.DependsOn)
	default:
		return false
	}
	return true
}

// lifecycle records the lifecycle settings policies inspect. Terraform requires literal
// values here, so they are evaluated without variables or functions.
func (d *resourceDecoder) lifecycle(b *hclsyntax.Block, r *Resource) {
	for _, a := range sortedSyntaxAttributes(b.Body.Attributes) {
		switch a.Name {
		case "prevent_destroy":
			v, diags := d.m.evalExpr(a.Expr, &hcl.EvalContext{})
			var err error
			if !diags.HasErrors() {
				// Terraform decodes it with conversion, so "true" is accepted.
				v, err = convert.Convert(v, cty.Bool)
			}
			if diags.HasErrors() || err != nil || !v.IsKnown() || v.IsMarked() || v.IsNull() {
				d.invalid(a.Expr, "Invalid prevent_destroy")
				continue
			}
			pd := v.True()
			r.Lifecycle.PreventDestroy = &pd
		case "ignore_changes":
			if hcl.ExprAsKeyword(a.Expr) == "all" {
				r.Lifecycle.IgnoreChanges = []string{"*"}
				continue
			}
			exprs, diags := hcl.ExprList(a.Expr)
			if diags.HasErrors() {
				d.invalid(a.Expr, "Invalid ignore_changes")
				continue
			}
			for _, e := range exprs {
				path, ok := relativePath(e)
				if !ok {
					d.invalid(e, "Invalid ignore_changes reference")
					continue
				}
				r.Lifecycle.IgnoreChanges = append(r.Lifecycle.IgnoreChanges, path)
			}
		}
	}
}

// relativePath returns the dot-joined attribute path a relative traversal such as
// tags["Name"] names ("tags.Name").
func relativePath(e hcl.Expression) (string, bool) {
	tr, diags := hcl.RelTraversalForExpr(e)
	if diags.HasErrors() || len(tr) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(tr))
	for _, step := range tr {
		switch s := step.(type) {
		case hcl.TraverseAttr:
			parts = append(parts, s.Name)
		case hcl.TraverseIndex:
			k := s.Key
			switch {
			case !k.IsKnown() || k.IsNull():
				return "", false
			case k.Type() == cty.String:
				parts = append(parts, k.AsString())
			case k.Type() == cty.Number:
				parts = append(parts, k.AsBigFloat().Text('f', -1))
			default:
				return "", false
			}
		default:
			return "", false
		}
	}
	return strings.Join(parts, "."), true
}

// invalid reports an expression Terraform would reject, without quoting it.
func (d *resourceDecoder) invalid(e hcl.Expression, summary string) {
	r := e.Range()
	d.m.diag(SeverityWarning, DiagEvaluation, summary,
		"Terraform would reject this meta-argument, so iace ignores it.",
		r.Filename, r.Start.Line, r.Start.Column)
}

// attribute evaluates one attribute within the size limits. Roots iace cannot resolve
// (resources, data sources, modules, count, each, self, terraform) are unknown. When an input is
// sensitive, an unknown result stays sensitive (fail closed). The exception is an expression
// too complex to inspect: its references are not walked, so its unknown is unmarked, which
// leaks nothing since an unknown holds no value (locals do the same).
func (d *resourceDecoder) attribute(a *hclsyntax.Attribute) cty.Value {
	calls, safe := d.m.inspectExpr(a.Expr)
	if !safe {
		v, _ := d.m.evalExpr(a.Expr, nil) // reports the expression as too complex
		return v
	}
	r := a.Expr.Range()
	ectx := &hcl.EvalContext{Variables: map[string]cty.Value{"var": d.vars}}
	locals := map[string]cty.Value{}
	est := r.End.Byte - r.Start.Byte
	sensitive := false
	// Each reference costs map lookups only: sizes and sensitivity are cached per value.
	for _, tr := range a.Expr.Variables() {
		root := tr.RootName()
		name, _ := traversalAttr(tr, 1)
		switch root {
		case "var":
			if d.vars.Type().HasAttribute(name) {
				v := d.vars.GetAttr(name)
				est += d.size("var."+name, v)
				sensitive = sensitive || d.isSensitive("var."+name, v)
			}
		case "local":
			if l, ok := d.locals[name]; ok {
				locals[name] = l.Value
				est += d.size("local."+name, l.Value)
				sensitive = sensitive || d.isSensitive("local."+name, l.Value)
			}
		case "path":
			ectx.Variables["path"] = pathObject()
			est++
		default:
			ectx.Variables[root] = cty.DynamicVal
			est++
		}
	}
	ectx.Variables["local"] = cty.ObjectVal(locals)
	ectx.Functions = d.m.functions(a.Expr, calls)
	unknown := cty.DynamicVal
	if sensitive {
		unknown = unknown.Mark(SensitiveMark)
	}
	if est > maxLocalValueSize || est > d.remaining {
		d.tooLarge(a, est <= maxLocalValueSize)
		return unknown
	}
	val, diags := d.m.evalExpr(a.Expr, ectx)
	if diags.HasErrors() {
		// hcl's Summary only: its Detail can quote values.
		summary := diags[0].Summary
		for _, dg := range diags {
			if dg.Severity == hcl.DiagError {
				summary = dg.Summary
				break
			}
		}
		d.m.diag(SeverityWarning, DiagEvaluation, summary,
			"The expression could not be evaluated, so its value is unknown.",
			r.Filename, r.Start.Line, r.Start.Column)
		return unknown
	}
	size, ok := valueSize(val, maxLocalValueSize, maxNesting)
	if !ok || size > d.remaining {
		d.tooLarge(a, ok)
		return unknown
	}
	d.remaining -= size
	return val
}

// tooLarge reports an attribute over the limit for one value at that attribute, and the first
// one past what remains of maxResourcesSize once for the module.
func (d *resourceDecoder) tooLarge(a *hclsyntax.Attribute, total bool) {
	r := a.NameRange
	switch {
	case !total:
		d.m.diag(SeverityWarning, DiagValueTooLarge, "Attribute value too large",
			fmt.Sprintf("The attribute %q would pass the size or nesting limit for evaluated values, so its value is unknown.", a.Name),
			r.Filename, r.Start.Line, r.Start.Column)
	case !d.totalWarned:
		d.totalWarned = true
		d.m.diag(SeverityWarning, DiagValueTooLarge, "Resource values too large together",
			fmt.Sprintf("The resources' attribute values reach the size limit for a module at %q: from there on, attributes that do not fit are unknown.", a.Name),
			r.Filename, r.Start.Line, r.Start.Column)
	}
}

// size returns the cached size of a variable or local's value.
func (d *resourceDecoder) size(key string, v cty.Value) int {
	if n, ok := d.sizes[key]; ok {
		return n
	}
	n, ok := valueSize(v, maxLocalValueSize, maxNesting)
	if !ok {
		n = maxLocalValueSize + 1
	}
	d.sizes[key] = n
	return n
}

// isSensitive returns whether a variable or local's value contains a sensitive value, cached.
func (d *resourceDecoder) isSensitive(key string, v cty.Value) bool {
	s, ok := d.sensitive[key]
	if !ok {
		s = v.ContainsMarked()
		d.sensitive[key] = s
	}
	return s
}

// pathObject is path.* for a module evaluated on its own: paths resolve against the module
// directory (see fileFunctions), so path.module is "."; the root module and working directory
// are not known.
func pathObject() cty.Value {
	return cty.ObjectVal(map[string]cty.Value{
		"module": cty.StringVal("."),
		"root":   cty.UnknownVal(cty.String),
		"cwd":    cty.UnknownVal(cty.String),
	})
}

// sortedSyntaxAttributes returns attrs in source order.
func sortedSyntaxAttributes(attrs hclsyntax.Attributes) []*hclsyntax.Attribute {
	out := make([]*hclsyntax.Attribute, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b *hclsyntax.Attribute) int {
		return a.SrcRange.Start.Byte - b.SrcRange.Start.Byte
	})
	return out
}
