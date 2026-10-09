package terraform

import (
	"context"
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// Output diagnostic codes.
const (
	// DiagMissingOutputValue: an output block has no value. Terraform rejects the module.
	DiagMissingOutputValue DiagCode = "missing_output_value"
	// DiagDuplicateOutput: an output is declared twice. Terraform rejects the module.
	DiagDuplicateOutput DiagCode = "duplicate_output"
)

var outputSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "value"}, {Name: "sensitive"}},
}

// Output is one evaluated output block.
type Output struct {
	Name string
	// Value is unknown, wholly or in part, where iace cannot evaluate it statically, and marked
	// sensitive when the output is or when it holds a sensitive value.
	Value cty.Value
	// Sensitive is the declared sensitive argument.
	Sensitive bool
	// Unknown lists the outermost unknown paths in Value, as Local.Unknown.
	Unknown   []cty.Path
	DeclRange hcl.Range
}

// evaluateOutputs evaluates the module's output blocks with vars, locals and modules as
// var.*, local.* and module.* (resourceDecoder.modules), within the size limits of resource
// attributes, in a budget of their own. A missing value or a duplicate name is an error as in
// Terraform; the first declaration is kept. What cannot be evaluated is unknown with a warning;
// only a cancelled context is an error.
func (m *ParsedModule) evaluateOutputs(ctx context.Context, vars map[string]Variable, locals map[string]Local, modules map[string]cty.Value) (map[string]Output, error) {
	d := m.newResourceDecoder(vars, locals)
	d.modules = modules
	out := map[string]Output{}
	for _, b := range m.Blocks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if b.Type != "output" || len(b.Labels) != 1 {
			continue
		}
		name, r := b.Labels[0], b.DefRange
		if _, dup := out[name]; dup {
			m.diag(SeverityError, DiagDuplicateOutput, "Duplicate output definition",
				fmt.Sprintf("An output named %q was already declared; this declaration is ignored.", name),
				b.File, r.Start.Line, r.Start.Column)
			continue
		}
		o := Output{Name: name, Value: cty.DynamicVal, DeclRange: b.DefRange}
		content, _, diags := b.Body.PartialContent(outputSchema)
		m.addHCLDiags(b.File, diags)
		if attr, ok := content.Attributes["sensitive"]; ok {
			// Fail closed, as for variables: anything but false keeps the output sensitive.
			s, diags := m.evalExpr(attr.Expr, nil)
			m.addHCLDiags(b.File, diags)
			o.Sensitive = true
			if bv, err := convert.Convert(s, cty.Bool); err == nil && !diags.HasErrors() && bv.IsKnown() && !bv.IsNull() {
				o.Sensitive = bv.True()
			}
		}
		if attr, ok := content.Attributes["value"]; ok {
			o.Value, _ = d.evalBounded(attr.Expr, name, attr.NameRange)
		} else {
			m.diag(SeverityError, DiagMissingOutputValue, "Missing required argument",
				fmt.Sprintf("The output %q has no value, so its value is unknown.", name),
				b.File, r.Start.Line, r.Start.Column)
		}
		if o.Sensitive {
			o.Value = o.Value.Mark(SensitiveMark)
		}
		o.Unknown = unknownPaths(o.Value)
		m.usage.unknown += pathSteps(o.Unknown)
		out[name] = o
	}
	m.usage.outputs = maxResourcesSize - d.remaining
	m.sortDiagnostics()
	return out, nil
}

// outputsObject is module.<name> for a called instance: an object of its outputs.
func outputsObject(outputs map[string]Output) cty.Value {
	attrs := make(map[string]cty.Value, len(outputs))
	for name, o := range outputs {
		attrs[name] = o.Value
	}
	return cty.ObjectVal(attrs)
}
