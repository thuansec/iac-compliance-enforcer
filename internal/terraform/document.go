package terraform

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// Unexpressed lists what a document cannot say by itself, for the coverage gaps that report it
// (T-0109d).
type Unexpressed struct {
	// IncompleteResources are the addresses of resources whose values NormalizeResource could
	// not express; they are in the document with empty values.
	IncompleteResources []string `json:"incomplete_resources"`
	// IncompleteReferences are the addresses of resources ("module.a.aws_s3_bucket.b") and
	// outputs ("module.a.output.o") whose references may be missing (ReferencesIncomplete).
	IncompleteReferences []string `json:"incomplete_references"`
}

// NormalizeRoot builds the input document v1 of one evaluated root module (HCL mode): the root's
// terraform settings and provider blocks, the provider versions of its lock file, its module
// calls, and the resources, variables and outputs of every evaluated instance, each sorted.
// Nothing is evaluated that Terraform would not evaluate: backend values are read from literals
// only, and provider blocks are not evaluated yet (T-0122), so every attribute and nested block
// they set is unknown.
func NormalizeRoot(rr RootResult) (*model.InputDocument, Unexpressed) {
	doc := &model.InputDocument{
		SchemaVersion:    model.InputSchemaVersion,
		Source:           model.DocumentSource{Kind: model.SourceHCL, RootModule: rr.Dir},
		Terraform:        model.TerraformSettings{RequiredProviders: map[string]model.ProviderRequirement{}},
		ProviderVersions: map[string]string{},
		Providers:        []model.ProviderConfig{},
		Resources:        []model.Resource{},
		ModuleCalls:      []model.ModuleCall{},
		Variables:        []model.Variable{},
		Outputs:          []model.Output{},
		CoverageGaps:     []model.CoverageGap{},
	}
	un := Unexpressed{IncompleteResources: []string{}, IncompleteReferences: []string{}}
	maps.Copy(doc.ProviderVersions, rr.ProviderVersions)
	if rr.Tree != nil && rr.Tree.Root != nil && rr.Tree.Root.Module != nil {
		m := rr.Tree.Root.Module
		doc.Terraform = terraformSettings(m)
		for _, p := range m.ProviderConfigs() {
			doc.Providers = append(doc.Providers, providerDocument(p))
		}
		doc.ModuleCalls = moduleCalls(rr.Tree.Root)
	}
	for _, inst := range rr.Instances {
		if inst.Skipped {
			continue
		}
		for _, r := range inst.Resources {
			res, complete := NormalizeResource(r)
			if !complete {
				un.IncompleteResources = append(un.IncompleteResources, r.Address)
			}
			if r.ReferencesIncomplete {
				un.IncompleteReferences = append(un.IncompleteReferences, r.Address)
			}
			doc.Resources = append(doc.Resources, res)
		}
		for _, v := range inst.Variables {
			doc.Variables = append(doc.Variables, model.Variable{
				Name: v.Name, Module: inst.Address, Sensitive: v.Sensitive, HasDefault: v.HasDefault, Type: v.Type,
			})
		}
		for _, o := range inst.Outputs {
			doc.Outputs = append(doc.Outputs, model.Output{
				Name:        o.Name,
				Module:      inst.Address,
				Sensitive:   o.Sensitive || hasSensitiveMark(o.Value),
				References:  slices.Sorted(slices.Values(o.References)),
				SourceRange: model.SourceLocation{File: o.DeclRange.Filename, Range: modelRange(o.DeclRange)},
			})
			if o.ReferencesIncomplete {
				un.IncompleteReferences = append(un.IncompleteReferences, qualify(inst.Address, "output."+o.Name))
			}
		}
	}
	slices.SortFunc(doc.Resources, func(a, b model.Resource) int { return cmp.Compare(a.Address, b.Address) })
	slices.SortFunc(doc.Variables, func(a, b model.Variable) int {
		return cmp.Or(cmp.Compare(a.Module, b.Module), cmp.Compare(a.Name, b.Name))
	})
	slices.SortFunc(doc.Outputs, func(a, b model.Output) int {
		return cmp.Or(cmp.Compare(a.Module, b.Module), cmp.Compare(a.Name, b.Name))
	})
	slices.Sort(un.IncompleteResources)
	slices.Sort(un.IncompleteReferences)
	return doc, un
}

// hasSensitiveMark reports whether v or any part of it is marked sensitive.
func hasSensitiveMark(v cty.Value) bool {
	_, marks := v.UnmarkDeepWithPaths()
	for _, pm := range marks {
		if _, ok := pm.Marks[SensitiveMark]; ok {
			return true
		}
	}
	return false
}

// qualify prefixes name with a module address, if there is one.
func qualify(module, name string) string {
	if module == "" {
		return name
	}
	return module + "." + name
}

var terraformSettingsSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "required_version"}},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "backend", LabelNames: []string{"type"}},
		{Type: "cloud"},
	},
}

// terraformSettings reads the module's terraform blocks without evaluation: every literal
// required_version, joined with ", " since Terraform enforces each of them, the first backend
// (or cloud, as type "cloud") block with its literal values, and required_providers.
func terraformSettings(m *ParsedModule) model.TerraformSettings {
	out := model.TerraformSettings{RequiredProviders: map[string]model.ProviderRequirement{}}
	var versions []string
	for name, rp := range m.RequiredProviders() {
		out.RequiredProviders[name] = model.ProviderRequirement{Source: rp.Source, Version: rp.Version}
	}
	for _, b := range m.Blocks {
		if b.Type != "terraform" {
			continue
		}
		content, _, _ := b.Body.PartialContent(terraformSettingsSchema)
		if a, ok := content.Attributes["required_version"]; ok {
			if v, ok := literalOnly(a.Expr).(string); ok && v != "" {
				versions = append(versions, v)
			}
		}
		for _, inner := range content.Blocks {
			if out.Backend != nil {
				break
			}
			typ := inner.Type
			if typ == "backend" {
				typ = inner.Labels[0]
			}
			values, unknown := literalBody(inner.Body)
			out.Backend = &model.Backend{Type: typ, Values: values, Unknown: unknown}
		}
	}
	out.RequiredVersion = strings.Join(versions, ", ")
	return out
}

// providerDocument describes a provider block. Its arguments are not evaluated yet (T-0122), so
// each attribute and nested block it sets, except the alias and version meta-arguments, is
// unknown: absent would wrongly tell a policy that the setting is not there.
func providerDocument(p ProviderConfig) model.ProviderConfig {
	out := model.ProviderConfig{
		LocalName:   p.LocalName,
		Alias:       p.Alias,
		Source:      p.Source,
		Values:      model.Values{},
		Unknown:     []model.Path{},
		Sensitive:   []model.Path{},
		SourceRange: model.SourceLocation{File: p.File, Range: modelRange(p.Range)},
	}
	for _, name := range bodyNames(p.Body) {
		if name == "alias" || name == "version" {
			continue
		}
		out.Values[name] = nil
		out.Unknown = append(out.Unknown, model.Path{model.AttrStep(name)})
	}
	return out
}

// literalBody reads a body without evaluation: each attribute whose expression is a literal
// string, number or bool is its value, and every other attribute and nested block is unknown.
func literalBody(body hcl.Body) (model.Values, []model.Path) {
	values, unknown := model.Values{}, []model.Path{}
	var attrs hcl.Attributes
	if sb, ok := body.(*hclsyntax.Body); ok {
		attrs = make(hcl.Attributes, len(sb.Attributes))
		for name, a := range sb.Attributes {
			attrs[name] = a.AsHCLAttribute()
		}
	} else {
		attrs, _ = body.JustAttributes()
	}
	for _, name := range bodyNames(body) {
		if a, ok := attrs[name]; ok {
			if v, ok := literalPrimitive(a.Expr); ok {
				values[name] = v
				continue
			}
		}
		values[name] = nil
		unknown = append(unknown, model.Path{model.AttrStep(name)})
	}
	return values, unknown
}

// bodyNames returns the names of the attributes and nested blocks a body sets, sorted and
// unique: a dynamic block counts as the block type it generates, and a body with override files
// merged in (mergedBody, maskedBody) lists what the base or any override sets. A JSON body
// cannot tell attributes from blocks and lists every property.
func bodyNames(body hcl.Body) []string {
	names := appendBodyNames(nil, body)
	slices.Sort(names)
	return slices.Compact(names)
}

func appendBodyNames(names []string, body hcl.Body) []string {
	switch b := body.(type) {
	case *mergedBody:
		names = appendBodyNames(names, b.base)
		for _, over := range b.overs {
			names = appendBodyNames(names, over)
		}
	case *maskedBody:
		for _, name := range appendBodyNames(nil, b.inner) {
			if !b.attrs[name] && !b.blocks[name] {
				names = append(names, name)
			}
		}
	case *hclsyntax.Body:
		for name := range b.Attributes {
			names = append(names, name)
		}
		for _, blk := range b.Blocks {
			if blk.Type == "dynamic" && len(blk.Labels) == 1 {
				names = append(names, blk.Labels[0])
				continue
			}
			names = append(names, blk.Type)
		}
	default:
		attrs, _ := body.JustAttributes()
		for name, a := range attrs {
			if name != "dynamic" {
				names = append(names, name)
				continue
			}
			// A JSON dynamic property is an object keyed by the generated block types.
			v, diags := a.Expr.Value(nil)
			if diags.HasErrors() || !v.IsKnown() || v.IsNull() || !v.Type().IsObjectType() && !v.Type().IsMapType() {
				names = append(names, name)
				continue
			}
			for label := range v.AsValueMap() {
				names = append(names, label)
			}
		}
	}
	return names
}

// literalPrimitive returns the value of a literal string, number or bool, normalized as in
// values (normalizeNumber). An HCL expression must be a literal or a template without
// interpolation; a JSON expression with no evaluation context is its literal value.
func literalPrimitive(expr hcl.Expression) (any, bool) {
	if !inJSON(expr) {
		switch e := expr.(type) {
		case *hclsyntax.TemplateExpr:
			if !e.IsStringLiteral() {
				return nil, false
			}
		case *hclsyntax.LiteralValueExpr:
		default:
			return nil, false
		}
	}
	v, diags := expr.Value(nil)
	if diags.HasErrors() || !v.IsKnown() || v.IsNull() {
		return nil, false
	}
	switch v.Type() {
	case cty.String:
		// Without an evaluation context a JSON string's template is not evaluated but returned
		// as written, so one that holds a template sequence is not a literal (escapes included,
		// which fails closed).
		if s := v.AsString(); !inJSON(expr) || !strings.Contains(s, "${") && !strings.Contains(s, "%{") {
			return s, true
		}
		return nil, false
	case cty.Bool:
		return v.True(), true
	case cty.Number:
		return normalizeNumber(v.AsBigFloat())
	}
	return nil, false
}

// literalOnly returns literalPrimitive's value, or nil when expr is not a literal.
func literalOnly(expr hcl.Expression) any {
	v, _ := literalPrimitive(expr)
	return v
}

// moduleCalls lists the calls of the tree under node, depth first, sorted by address.
func moduleCalls(node *ModuleNode) []model.ModuleCall {
	out := []model.ModuleCall{}
	var walk func(n *ModuleNode)
	walk = func(n *ModuleNode) {
		for _, c := range n.Calls {
			out = append(out, model.ModuleCall{
				Address:     c.Address,
				Source:      c.Source,
				Version:     c.Version,
				Resolved:    c.Child != nil,
				Reason:      string(c.Unresolved),
				SourceRange: model.SourceLocation{File: c.File, Range: modelRange(c.Range)},
			})
			if c.Child != nil {
				walk(c.Child)
			}
		}
	}
	walk(node)
	// Addresses are unique: a tree node's calls are declared once each (duplicate_module).
	slices.SortFunc(out, func(a, b model.ModuleCall) int { return cmp.Compare(a.Address, b.Address) })
	return out
}
