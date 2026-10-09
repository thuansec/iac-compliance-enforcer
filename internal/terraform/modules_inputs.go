package terraform

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// Module input diagnostic codes.
const (
	// DiagMissingModuleInput: a module call does not set a variable that has no default.
	// Terraform rejects the configuration.
	DiagMissingModuleInput DiagCode = "missing_module_input"
	// DiagUndeclaredModuleInput: a module call sets an argument the module declares no variable
	// for. Terraform rejects the configuration.
	DiagUndeclaredModuleInput DiagCode = "undeclared_module_input"
)

// moduleMetaArguments are the module call arguments that are not inputs.
var moduleMetaArguments = map[string]bool{
	"source": true, "version": true, "count": true, "for_each": true, "providers": true, "depends_on": true,
}

// Input is one argument of a module call, evaluated in the caller's context.
type Input struct {
	Value cty.Value
	// Range is the expression's range and NameRange the argument name's, in the caller's file.
	Range, NameRange hcl.Range
}

// NewInstance returns a module instance over m's parse: it shares the blocks, which evaluation
// only reads, and starts with its own source map (EvaluateVariables adds tfvars sources to it),
// diagnostics, function table and work, file reads and regex cache. Each module call evaluates
// in its own instance, so instances of one directory never share budgets or diagnostics; parse
// diagnostics stay on m.
func (m *ParsedModule) NewInstance() *ParsedModule {
	return &ParsedModule{Dir: m.Dir, Blocks: m.Blocks, src: maps.Clone(m.src), root: m.root}
}

// ModuleInputs evaluates the arguments of a module call of m, which is the caller, with vars as
// var.* and locals as local.*, within the size limits of resource attributes (maxLocalValueSize
// each, and maxResourcesSize for the inputs of all of m's calls together). Module outputs, resources and every other reference are
// unknown. Meta-arguments are not inputs. A nested block is an error, as in Terraform. What
// cannot be evaluated is unknown with a warning; only a cancelled context is an error.
func (m *ParsedModule) ModuleInputs(ctx context.Context, call *ModuleCall, vars map[string]Variable, locals map[string]Local) (map[string]Input, error) {
	attrs, diags := call.Body.JustAttributes()
	m.addHCLDiags(call.File, diags)
	// The inputs of all of m's calls share one size budget, as its resources do.
	d := m.newResourceDecoder(vars, locals)
	d.remaining = maxResourcesSize - m.usage.inputs
	defer func() { m.usage.inputs = maxResourcesSize - d.remaining }()
	out := map[string]Input{}
	for _, a := range sortedAttributes(attrs) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if moduleMetaArguments[a.Name] {
			continue
		}
		v, _ := d.evalBounded(a.Expr, a.Name, a.NameRange)
		out[a.Name] = Input{Value: v, Range: a.Expr.Range(), NameRange: a.NameRange}
	}
	m.sortDiagnostics()
	return out, nil
}

// EvaluateModuleVariables evaluates m's variables as the child module that call loads: each
// takes its input from inputs (ModuleInputs), else its default, and is then converted, defaulted
// and marked as in EvaluateVariables. A variable without a default that call does not set is
// unknown, and an input m declares no variable for is ignored: both are errors, as in Terraform,
// reported at the call in the caller's file. tfvars files and command-line values apply only to
// root modules. Only a cancelled context is an error.
func (m *ParsedModule) EvaluateModuleVariables(ctx context.Context, call *ModuleCall, inputs map[string]Input) (map[string]Variable, error) {
	vars := m.declareVariables()
	for _, name := range slices.Sorted(maps.Keys(inputs)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		in := inputs[name]
		v, ok := vars[name]
		if !ok {
			r := in.NameRange
			m.diag(SeverityError, DiagUndeclaredModuleInput, "Unsupported argument",
				fmt.Sprintf("The module declares no variable named %q, so this argument is ignored.", name),
				r.Filename, r.Start.Line, r.Start.Column)
			continue
		}
		v.set(in.Value, in.Range)
	}
	out := make(map[string]Variable, len(vars))
	for _, name := range slices.Sorted(maps.Keys(vars)) {
		v := vars[name]
		if _, given := inputs[name]; !given && !v.HasDefault {
			r := call.DefRange
			m.diag(SeverityError, DiagMissingModuleInput, "Missing required argument",
				fmt.Sprintf("The module call does not set the variable %q, which has no default, so its value is unknown.", name),
				call.File, r.Start.Line, r.Start.Column)
		}
		out[name] = m.finishVariable(v)
	}
	m.sortDiagnostics()
	return out, nil
}
