package terraform

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// SensitiveMark is the cty mark on values of sensitive variables. Later stages propagate it and
// list the marked paths in the input document's sensitive arrays.
const SensitiveMark = "sensitive"

// Diagnostic codes for variable evaluation.
const (
	// DiagVariableType: a value does not convert to the variable's declared type; it is kept
	// unconverted.
	DiagVariableType DiagCode = "variable_type"
	// DiagUndeclaredVariable: a tfvars file sets a variable the module does not declare.
	DiagUndeclaredVariable DiagCode = "undeclared_variable"
	// DiagDuplicateVariable: a variable is declared twice. Terraform rejects the module.
	DiagDuplicateVariable DiagCode = "duplicate_variable"
	// DiagFileLimit: a module directory holds more automatic tfvars files than Limits.MaxFiles;
	// none of them is read, because applying only some would give wrong values.
	DiagFileLimit DiagCode = "file_limit"
)

// VarOptions are the variable values given on the command line. They come from the pipeline,
// not the scanned repository, so mistakes in them are errors.
type VarOptions struct {
	// VarFiles are tfvars files relative to the scan root, applied in order.
	VarFiles []string
	// Vars are NAME=VALUE pairs, applied in order after VarFiles.
	Vars []string
}

// Variable is a root-module input variable and its value.
type Variable struct {
	Name string
	// Type is the declared type constraint, "any" when none is declared.
	Type       string
	HasDefault bool
	Sensitive  bool
	// Value is unknown when no source sets it, and marked with SensitiveMark when Sensitive.
	Value cty.Value
	// References are the addresses the module input that set the variable refers to,
	// qualified in the caller (EvaluateModuleVariables); none for root variables.
	// ReferencesIncomplete reports that some may be missing.
	References           []string
	ReferencesIncomplete bool
	DeclRange            hcl.Range
}

var variableSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "default"}, {Name: "type"}, {Name: "sensitive"}, {Name: "nullable"}},
}

// varState is a variable while its value sources are applied.
type varState struct {
	Variable
	ty cty.Type
	// defaults fills optional object attributes, as optional(T, default) declares.
	defaults *typeexpr.Defaults
	// def is the default value; nullable=false replaces a null value with it.
	def      cty.Value
	nullable bool
	// parseFlag: a --var value is parsed as an expression, not taken literally. As in
	// Terraform, that holds for complex types and an explicit `any`, not for a missing type.
	parseFlag bool
	from      hcl.Range // where the current value came from
	isSet     bool
}

// EvaluateVariables evaluates the module's variable blocks as a root module, applying values
// in Terraform's precedence: default, terraform.tfvars, terraform.tfvars.json, *.auto.tfvars and
// *.auto.tfvars.json in lexical order (all in the module directory), opts.VarFiles in order,
// then opts.Vars in order. Values are literals: everything is evaluated through evalExpr with no
// context. Problems in the repository's files are diagnostics; problems with opts, or a file
// that cannot be read, are errors.
func (m *ParsedModule) EvaluateVariables(ctx context.Context, root *fsutil.Root, opts VarOptions, limits Limits) (map[string]Variable, error) {
	vars := m.declareVariables()

	files, err := m.tfvarsFiles(root)
	if err != nil {
		return nil, err
	}
	for _, f := range opts.VarFiles {
		if err := checkVarFilePath(f); err != nil {
			return nil, err
		}
	}
	if len(files) > limits.MaxFiles {
		m.diag(SeverityError, DiagFileLimit, "Too many tfvars files",
			fmt.Sprintf("The module directory holds %d automatic tfvars files, more than the limit of %d, so none was read.",
				len(files), limits.MaxFiles), m.Dir, 0, 0)
		files = nil
	}
	for _, f := range append(files, opts.VarFiles...) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := m.applyVarsFile(root, f, limits, vars); err != nil {
			return nil, err
		}
	}
	for i, kv := range opts.Vars {
		if err := m.applyVarFlag(i, kv, vars); err != nil {
			return nil, err
		}
	}

	out := make(map[string]Variable, len(vars))
	for name, v := range vars {
		out[name] = m.finishVariable(v)
	}
	m.sortDiagnostics()
	return out, nil
}

// declareVariables reads the module's variable blocks, keeping the first of duplicates.
func (m *ParsedModule) declareVariables() map[string]*varState {
	vars := map[string]*varState{}
	for _, b := range m.Blocks {
		if b.Type != "variable" || len(b.Labels) != 1 {
			continue
		}
		v := m.declareVariable(b)
		first, dup := vars[v.Name]
		if !dup {
			vars[v.Name] = v
			continue
		}
		// Terraform rejects the module. Keep the first declaration, but a second one can
		// never make a sensitive variable non-sensitive.
		first.Sensitive = first.Sensitive || v.Sensitive
		m.diag(SeverityError, DiagDuplicateVariable, "Duplicate variable declaration",
			fmt.Sprintf("A variable named %q was already declared; this declaration is ignored.", v.Name),
			b.File, b.DefRange.Start.Line, b.DefRange.Start.Column)
	}
	return vars
}

// declareVariable reads a variable block's type, default and sensitivity.
func (m *ParsedModule) declareVariable(b Block) *varState {
	v := &varState{Variable: Variable{Name: b.Labels[0], DeclRange: b.DefRange}, ty: cty.DynamicPseudoType, nullable: true}
	content, _, diags := b.Body.PartialContent(variableSchema)
	m.addHCLDiags(b.File, diags)
	if attr, ok := content.Attributes["type"]; ok && !m.safeTypeExpr(attr.Expr) {
		r := attr.Expr.Range()
		m.diag(SeverityWarning, DiagExpressionTooComplex, "Expression too complex",
			"The type constraint is nested too deeply to read safely, so the variable's type is unknown.",
			r.Filename, r.Start.Line, r.Start.Column)
	} else if ok {
		ty, defaults, diags := typeexpr.TypeConstraintWithDefaults(attr.Expr)
		m.addHCLDiags(b.File, diags)
		if !diags.HasErrors() {
			v.ty, v.defaults = ty, defaults
			v.parseFlag = !ty.IsPrimitiveType()
		}
	}
	if attr, ok := content.Attributes["sensitive"]; ok {
		// Fail closed: anything but a value that converts to false keeps the variable sensitive.
		s, diags := m.evalExpr(attr.Expr, nil)
		m.addHCLDiags(b.File, diags)
		v.Sensitive = true
		if bv, err := convert.Convert(s, cty.Bool); err == nil && !diags.HasErrors() && bv.IsKnown() && !bv.IsNull() {
			v.Sensitive = bv.True()
		}
	}
	if attr, ok := content.Attributes["nullable"]; ok {
		n, diags := m.evalExpr(attr.Expr, nil)
		m.addHCLDiags(b.File, diags)
		if bv, err := convert.Convert(n, cty.Bool); err == nil && bv.IsKnown() && !bv.IsNull() {
			v.nullable = bv.True()
		}
	}
	if attr, ok := content.Attributes["default"]; ok {
		val, diags := m.evalExpr(attr.Expr, nil)
		m.addHCLDiags(b.File, diags)
		v.HasDefault, v.def = true, val
		v.set(val, attr.Expr.Range())
	}
	return v
}

func (v *varState) set(val cty.Value, from hcl.Range) {
	v.Value, v.from, v.isSet = val, from, true
}

// tfvarsFiles lists the module directory's automatic tfvars files in precedence order.
func (m *ParsedModule) tfvarsFiles(root *fsutil.Root) ([]string, error) {
	entries, err := root.ReadDir(m.Dir)
	if err != nil {
		return nil, err
	}
	var main, auto []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case name == "terraform.tfvars" || name == "terraform.tfvars.json":
			main = append(main, join(m.Dir, name)) // ReadDir is sorted: .tfvars before .tfvars.json
		case strings.HasSuffix(name, ".auto.tfvars") || strings.HasSuffix(name, ".auto.tfvars.json"):
			auto = append(auto, join(m.Dir, name))
		}
	}
	return append(main, auto...), nil
}

// checkVarFilePath accepts only clean relative paths inside the scan root. fsutil confines the
// read anyway; this gives a clear error for a pipeline mistake.
func checkVarFilePath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, `\`) || (len(p) > 1 && p[1] == ':') {
		return fmt.Errorf("var file %q: must be a slash-separated path relative to the scan root", p)
	}
	if c := path.Clean(p); c == ".." || strings.HasPrefix(c, "../") {
		return fmt.Errorf("var file %q: leaves the scan root", p)
	}
	return nil
}

// applyVarsFile parses one tfvars file and applies its values.
func (m *ParsedModule) applyVarsFile(root *fsutil.Root, name string, limits Limits, vars map[string]*varState) error {
	data, err := root.ReadFile(name, limits.MaxFileSize)
	if err != nil {
		return err
	}
	if m.src == nil {
		m.src = map[string][]byte{}
	}
	// Values are evaluated here, so the tfvars source is dropped afterwards, unless the file is
	// one of the module's own (a --var-file may name one), whose source later stages need.
	if _, own := m.src[name]; !own {
		m.src[name] = data
		defer delete(m.src, name)
	}
	if err := checkNesting(name, data); err != nil {
		line := 0
		if ne, ok := errors.AsType[*nestingError](err); ok {
			line = ne.line
		}
		m.diag(SeverityError, DiagNestingTooDeep, "Nesting too deep",
			"The file nests expressions too deeply to parse safely, so it was not parsed.", name, line, 0)
		return nil
	}
	parser := hclparse.NewParser()
	var file *hcl.File
	var diags hcl.Diagnostics
	if strings.HasSuffix(name, ".json") {
		file, diags = parser.ParseJSON(data, name)
	} else {
		file, diags = parser.ParseHCL(data, name)
	}
	m.addHCLDiags(name, diags)
	if file == nil || diags.HasErrors() {
		return nil
	}
	attrs, diags := file.Body.JustAttributes()
	m.addHCLDiags(name, diags)
	for _, attr := range sortedAttributes(attrs) {
		v, ok := vars[attr.Name]
		if !ok {
			m.diag(SeverityWarning, DiagUndeclaredVariable, "Value for undeclared variable",
				fmt.Sprintf("The module declares no variable named %q, so this value is ignored.", attr.Name),
				name, attr.NameRange.Start.Line, attr.NameRange.Start.Column)
			continue
		}
		val, diags := m.evalExpr(attr.Expr, nil)
		m.addHCLDiags(name, diags)
		if diags.HasErrors() {
			val = cty.DynamicVal
		}
		v.set(val, attr.Expr.Range())
	}
	return nil
}

// applyVarFlag applies the i-th --var NAME=VALUE. As in Terraform, a variable with a primitive
// type or no type takes VALUE literally; a complex type or an explicit `any` parses it as an
// expression. A value that does not convert to the declared type is an error, as in Terraform.
func (m *ParsedModule) applyVarFlag(i int, kv string, vars map[string]*varState) error {
	name, raw, ok := strings.Cut(kv, "=")
	if !ok || name == "" {
		// The argument is not echoed: a mistaken --var "$SECRET" would end up in CI logs.
		return fmt.Errorf("--var argument %d: want NAME=VALUE", i+1)
	}
	v, ok := vars[name]
	if !ok {
		return fmt.Errorf("--var %q: the module declares no such variable", name)
	}
	if !v.parseFlag {
		return v.setFlag(cty.StringVal(raw))
	}
	file := "--var " + name
	src := []byte(raw)
	tokens, _ := hclsyntax.LexExpression(src, file, hcl.InitialPos)
	if err := scanTokens(tokens, maxOperators); err != nil {
		return fmt.Errorf("--var %q: %w", name, err)
	}
	expr, diags := hclsyntax.ParseExpression(src, file, hcl.InitialPos)
	if diags.HasErrors() {
		return fmt.Errorf("--var %q: not a valid expression: %s", name, diags[0].Summary)
	}
	if m.src == nil {
		m.src = map[string][]byte{}
	}
	m.src[file] = src
	val, diags := m.evalExpr(expr, nil)
	delete(m.src, file)
	if diags.HasErrors() {
		return fmt.Errorf("--var %q: %s", name, diags[0].Summary)
	}
	return v.setFlag(val)
}

// setFlag applies a command-line value, converted to the declared type now so that a mismatch
// is an error for the pipeline rather than a warning without a location.
func (v *varState) setFlag(val cty.Value) error {
	if v.ty != cty.DynamicPseudoType && val.IsWhollyKnown() {
		converted, err := v.convert(val)
		if err != nil {
			return fmt.Errorf("--var %q: not a valid %s", v.Name, typeexpr.TypeString(v.ty))
		}
		val = converted
	}
	v.set(val, hcl.Range{})
	return nil
}

// convert applies optional-attribute defaults, then converts to the declared type.
func (v *varState) convert(val cty.Value) (cty.Value, error) {
	if v.defaults != nil {
		val = v.defaults.Apply(val)
	}
	return convert.Convert(val, v.ty)
}

// finishVariable converts the value to the declared type and marks sensitive values.
func (m *ParsedModule) finishVariable(v *varState) Variable {
	out := v.Variable
	out.Type = typeexpr.TypeString(v.ty)
	if v.isSet && !v.nullable && v.HasDefault && v.Value.IsKnown() && v.Value.IsNull() {
		out.Value = v.def // nullable = false: null means "use the default", as in Terraform
	}
	switch {
	case !v.isSet:
		out.Value = cty.UnknownVal(v.ty)
	case v.ty != cty.DynamicPseudoType && out.Value.IsWhollyKnown():
		// A module input can hold sensitive values. Conversion can change the value's shape,
		// so marks are taken off and, failing closed, put back on the whole value.
		val, marks := out.Value.UnmarkDeep()
		converted, err := v.convert(val)
		if len(marks) > 0 {
			converted = converted.WithMarks(marks)
		}
		if err != nil {
			m.diag(SeverityWarning, DiagVariableType, "Value does not match the variable type",
				fmt.Sprintf("The value of variable %q is not a valid %s, so it is used unconverted.", v.Name, out.Type),
				v.from.Filename, v.from.Start.Line, v.from.Start.Column)
		} else {
			out.Value = converted
		}
	}
	if out.Sensitive {
		out.Value = out.Value.Mark(SensitiveMark)
	}
	return out
}

// safeTypeExpr checks a type expression before typeexpr walks it. In .tf.json a type is a string
// that hcl parses as an expression, so each string is lexed and checked like an expression.
func (m *ParsedModule) safeTypeExpr(expr hcl.Expression) bool {
	r := expr.Range()
	if !strings.HasSuffix(r.Filename, ".json") {
		return m.safeToEvaluate(expr)
	}
	src, ok := m.src[r.Filename]
	if !ok || r.Start.Byte < 0 || r.Start.Byte > r.End.Byte || r.End.Byte > len(src) {
		return false
	}
	dec := jsontext.NewDecoder(bytes.NewReader(src[r.Start.Byte:r.End.Byte]),
		jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			return true
		}
		if err != nil {
			return false
		}
		if tok.Kind() == '"' {
			tokens, _ := hclsyntax.LexExpression([]byte(tok.String()), r.Filename, hcl.InitialPos)
			if scanTokens(tokens, maxOperators) != nil {
				return false
			}
		}
	}
}

// sortedAttributes returns attributes in source order, so diagnostics and later values are
// deterministic.
func sortedAttributes(attrs hcl.Attributes) []*hcl.Attribute {
	out := make([]*hcl.Attribute, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b *hcl.Attribute) int { return a.Range.Start.Byte - b.Range.Start.Byte })
	return out
}
