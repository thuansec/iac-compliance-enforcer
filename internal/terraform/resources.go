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
	// DiagUnknownExpansion: count or for_each is not known statically, so the resource is one
	// placeholder instance ("type.name[*]") evaluated with an unknown count.index or each.
	DiagUnknownExpansion DiagCode = "unknown_expansion"
	// DiagInvalidExpansion: count or for_each has a value Terraform rejects (negative,
	// fractional, sensitive, a list, both set together, ...); the resource is a placeholder.
	DiagInvalidExpansion DiagCode = "invalid_expansion"
	// DiagExpansionLimit: a resource has more instances than maxInstancesPerResource, or the
	// module more than maxInstancesPerModule; the instances past the limit are not decoded.
	DiagExpansionLimit DiagCode = "expansion_limit"
)

// Limits on count and for_each expansion. Each instance evaluates the whole block again, so
// maxExpansionWork bounds the source bytes evaluated for instances after each block's first
// (instanceCost):
// otherwise a large body times many instances could take hours. Evaluating a block costs 200
// to 630ns per byte (a tuple of 200 numbers took 2.6s for 2^22 bytes), so 2^21 is about a second
// at worst.
const (
	maxInstancesPerResource = 10_000
	maxInstancesPerModule   = 100_000
	maxExpansionWork        = 1 << 21
	// maxInstanceStructure bounds, in estimated bytes, the structure of a module's decoded
	// instances that maxResourcesSize does not count: each instance's Resource and maps, and an
	// entry per attribute and nested block (instanceStructure). Values are counted separately.
	maxInstanceStructure = 1 << 27
	// instanceOverhead, attributeOverhead and blockOverhead are the estimated bytes of one
	// decoded instance and of each of its attributes and nested blocks. Measured live heap per
	// instance: 660 bytes bare, about 240 more per attribute, and about 170 per empty block or
	// 710 per block holding blocks (TestExpansionHeap).
	instanceOverhead  = 1024
	attributeOverhead = 256
	blockOverhead     = 768
)

// maxResourcesSize bounds the attribute values of all of a module's resources together, in
// valueSize units, as maxLocalsSize bounds locals: each value is walked a few times (measured,
// then for its unknown paths), so 2^24 units took about 4s. One attribute is bounded by
// maxLocalValueSize.
const maxResourcesSize = 1 << 22

// Resource is one instance of a resource or data source block, decoded without a provider
// schema: a block with count or for_each has one Resource per instance.
type Resource struct {
	Mode model.ResourceMode
	Type string
	Name string
	// Address is the instance address: BaseAddress followed by "[0]", `["key"]`, or "[*]" for
	// the placeholder of an unknown or invalid expansion.
	Address string
	// BaseAddress is "type.name" or "data.type.name".
	BaseAddress string
	// Index is the instance key; NoKey without count or for_each and for a placeholder.
	Index model.InstanceKey
	// CountUnknown and ForEachUnknown mark a placeholder: count or for_each was unknown or
	// invalid (both when they are set together).
	CountUnknown, ForEachUnknown bool
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
	// inst holds count and each for the instance being decoded, with their sizes and whether
	// they contain a sensitive value; instances counts the module's instances.
	inst          map[string]cty.Value
	instSizes     map[string]int
	instSensitive map[string]bool
	instances     int
	// expansionWork is the source bytes evaluated for repeated instances, at most
	// maxExpansionWork; structure is the instances' estimated structure, at most
	// maxInstanceStructure.
	expansionWork int
	structure     int
}

// instanceSpec is one instance to decode: its key, address suffix and count or each.
type instanceSpec struct {
	key    model.InstanceKey
	suffix string
	vars   map[string]cty.Value
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
		base := Resource{Type: b.Labels[0], Name: b.Labels[1], File: b.File, Range: b.Range, DefRange: b.DefRange}
		if b.Type == "resource" {
			base.Mode, base.BaseAddress = model.ModeManaged, base.Type+"."+base.Name
		} else {
			base.Mode, base.BaseAddress = model.ModeData, "data."+base.Type+"."+base.Name
		}
		body, ok := b.Body.(*hclsyntax.Body)
		if !ok {
			m.diag(SeverityWarning, DiagJSONBodyNotDecoded, "Resource in JSON syntax not decoded",
				"iace does not decode resources written in JSON syntax yet, so this resource's values are unknown.",
				b.File, b.DefRange.Start.Line, b.DefRange.Start.Column)
			base.Address, base.Value, base.Unknown = base.BaseAddress, cty.DynamicVal, []cty.Path{{}}
			base.Attributes = map[string]hcl.Range{}
			out = append(out, base)
			continue
		}
		d.metaArguments(body, &base)
		cost, structure := instanceCost(body), instanceStructure(body)
		for i, spec := range d.expand(&base) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if d.instances >= maxInstancesPerModule || d.structure+structure > maxInstanceStructure ||
				i > 0 && d.expansionWork+cost > maxExpansionWork {
				d.moduleLimit(&base)
				break
			}
			if i > 0 {
				d.expansionWork += cost
			}
			d.structure += structure
			d.instances++
			r := base
			r.Address, r.Index = base.BaseAddress+spec.suffix, spec.key
			r.Attributes = map[string]hcl.Range{}
			d.setInstance(spec.vars)
			r.Value = d.body(body, "", &r, true)
			r.Unknown = unknownPaths(r.Value)
			out = append(out, r)
		}
		d.setInstance(nil)
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
		if top && isMetaArgument(a.Name) {
			continue // recorded once by metaArguments
		}
		r.Attributes[prefix+a.Name] = a.Expr.Range()
		attrs[a.Name] = d.attribute(a)
	}
	blocks := map[string][]cty.Value{}
	dynamic := map[string]bool{}
	for _, b := range body.Blocks {
		switch {
		case top && (b.Type == "lifecycle" || b.Type == "provisioner" || b.Type == "connection"):
			continue // lifecycle is recorded by metaArguments; the others run at apply time
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

// instanceCost is the source an instance of a resource body evaluates: one, plus the bytes of
// its attributes and nested blocks other than meta-arguments, which are evaluated once.
func instanceCost(body *hclsyntax.Body) int {
	cost := 1
	for _, a := range body.Attributes {
		if !isMetaArgument(a.Name) {
			cost += a.SrcRange.End.Byte - a.SrcRange.Start.Byte
		}
	}
	for _, b := range body.Blocks {
		if b.Type != "lifecycle" && b.Type != "provisioner" && b.Type != "connection" {
			r := b.Range()
			cost += r.End.Byte - r.Start.Byte
		}
	}
	return cost
}

// instanceStructure estimates the bytes of one decoded instance of body, values aside:
// instanceOverhead, plus attributeOverhead per attribute and blockOverhead per nested block at
// any depth (meta-arguments included; a dynamic block counts once). Recursion follows block
// nesting, which the nesting guard bounds.
func instanceStructure(body *hclsyntax.Body) int {
	n := instanceOverhead + attributeOverhead*len(body.Attributes)
	for _, b := range body.Blocks {
		n += blockOverhead
		if b.Type != "dynamic" {
			n += instanceStructure(b.Body) - instanceOverhead
		}
	}
	return n
}

// isMetaArgument reports whether name is a meta-argument attribute of a resource body.
func isMetaArgument(name string) bool {
	switch name {
	case "count", "for_each", "provider", "depends_on":
		return true
	}
	return false
}

// metaArguments records the meta-arguments of a resource body in r, once for all its instances.
func (d *resourceDecoder) metaArguments(body *hclsyntax.Body, r *Resource) {
	for _, a := range sortedSyntaxAttributes(body.Attributes) {
		d.meta(a, r)
	}
	for _, b := range body.Blocks {
		if b.Type == "lifecycle" {
			d.lifecycle(b, r)
		}
	}
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
	v, _ := d.evalBounded(a.Expr, a.Name, a.NameRange)
	return v
}

// evalBounded evaluates expr, the value of the attribute name at nameRange, as attribute does.
// ok is false when it was not evaluated or failed, which has been reported; the value is then
// unknown.
func (d *resourceDecoder) evalBounded(expr hcl.Expression, name string, nameRange hcl.Range) (val cty.Value, ok bool) {
	calls, safe := d.m.inspectExpr(expr)
	if !safe {
		v, _ := d.m.evalExpr(expr, nil) // reports the expression as too complex
		return v, false
	}
	r := expr.Range()
	ectx := &hcl.EvalContext{Variables: map[string]cty.Value{"var": d.vars}}
	locals := map[string]cty.Value{}
	est := r.End.Byte - r.Start.Byte
	sensitive := false
	// Each reference costs map lookups only: sizes and sensitivity are cached per value.
	for _, tr := range expr.Variables() {
		root := tr.RootName()
		attr, _ := traversalAttr(tr, 1)
		switch root {
		case "var":
			if d.vars.Type().HasAttribute(attr) {
				v := d.vars.GetAttr(attr)
				est += d.size("var."+attr, v)
				sensitive = sensitive || d.isSensitive("var."+attr, v)
			}
		case "local":
			if l, ok := d.locals[attr]; ok {
				locals[attr] = l.Value
				est += d.size("local."+attr, l.Value)
				sensitive = sensitive || d.isSensitive("local."+attr, l.Value)
			}
		case "path":
			ectx.Variables["path"] = pathObject()
			est++
		case "count", "each":
			v, ok := d.inst[root]
			if !ok {
				ectx.Variables[root] = cty.DynamicVal
				est++
				break
			}
			ectx.Variables[root] = v
			est += d.instSizes[root]
			sensitive = sensitive || d.instSensitive[root]
		default:
			ectx.Variables[root] = cty.DynamicVal
			est++
		}
	}
	ectx.Variables["local"] = cty.ObjectVal(locals)
	ectx.Functions = d.m.functions(expr, calls)
	unknown := cty.DynamicVal
	if sensitive {
		unknown = unknown.Mark(SensitiveMark)
	}
	if est > maxLocalValueSize || est > d.remaining {
		d.tooLarge(name, nameRange, est <= maxLocalValueSize)
		return unknown, false
	}
	val, diags := d.m.evalExpr(expr, ectx)
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
		return unknown, false
	}
	size, ok := valueSize(val, maxLocalValueSize, maxNesting)
	if !ok || size > d.remaining {
		d.tooLarge(name, nameRange, ok)
		return unknown, false
	}
	d.remaining -= size
	return val, true
}

// tooLarge reports an attribute over the limit for one value at that attribute, and the first
// one past what remains of maxResourcesSize once for the module.
func (d *resourceDecoder) tooLarge(name string, r hcl.Range, total bool) {
	switch {
	case !total:
		d.m.diag(SeverityWarning, DiagValueTooLarge, "Attribute value too large",
			fmt.Sprintf("The attribute %q would pass the size or nesting limit for evaluated values, so its value is unknown.", name),
			r.Filename, r.Start.Line, r.Start.Column)
	case !d.totalWarned:
		d.totalWarned = true
		d.m.diag(SeverityWarning, DiagValueTooLarge, "Resource values too large together",
			fmt.Sprintf("The resources' attribute values reach the size limit for a module at %q: from there on, attributes that do not fit are unknown.", name),
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
