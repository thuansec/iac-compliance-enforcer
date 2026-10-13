package terraform

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/bits"
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
	defer m.forgetInspections()
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
			"The type constraint is nested too deeply, or has a for expression, to read safely, so the variable's type is unknown.",
			r.Filename, r.Start.Line, r.Start.Column)
	} else if ok && !m.chargeOptionalDefaults(attr.Expr) {
		r := attr.Expr.Range()
		m.diag(SeverityWarning, DiagExpressionTooComplex, "Optional defaults not read",
			"An optional attribute default in the type constraint is not a static value, or is too costly to convert, so the variable's type is unknown.",
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
	// Values are evaluated here, so the tfvars source is dropped afterwards, unless the file is
	// one of the module's own (a --var-file may name one), whose source later stages need.
	if _, own := m.src[name]; !own {
		m.setSource(name, data)
		defer m.dropSource(name)
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
	// A tfvars file is untrusted input read once here: its diagnostics share the per-file cap
	// of parsing (parseDiag, ADR 0016).
	parser := hclparse.NewParser()
	var file *hcl.File
	var diags hcl.Diagnostics
	if strings.HasSuffix(name, ".json") {
		file, diags = parser.ParseJSON(data, name)
	} else {
		file, diags = parser.ParseHCL(data, name)
		if body, ok := file.Body.(*hclsyntax.Body); ok && !diags.HasErrors() {
			rewriteForExprs(body)
		}
	}
	m.addParseDiags(name, diags)
	if file == nil || diags.HasErrors() {
		return nil
	}
	attrs, diags := file.Body.JustAttributes()
	m.addParseDiags(name, diags)
	for _, attr := range sortedAttributes(attrs) {
		v, ok := vars[attr.Name]
		if !ok {
			m.parseDiag(SeverityWarning, DiagUndeclaredVariable, "Value for undeclared variable",
				fmt.Sprintf("The module declares no variable named %q, so this value is ignored.", attr.Name),
				name, attr.NameRange.Start.Line, attr.NameRange.Start.Column)
			continue
		}
		val, diags := m.evalExpr(attr.Expr, nil)
		m.addParseDiags(name, diags)
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
		return m.setFlag(v, cty.StringVal(raw))
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
	rewriteForExprs(expr)
	m.setSource(file, src)
	val, diags := m.evalExpr(expr, nil)
	m.dropSource(file)
	if diags.HasErrors() {
		return fmt.Errorf("--var %q: %s", name, diags[0].Summary)
	}
	return m.setFlag(v, val)
}

// setFlag applies a command-line value, converted to the declared type now so that a mismatch
// is an error for the pipeline rather than a warning without a location. A value too large to
// convert is kept as given, and finishVariable makes it unknown.
func (m *ParsedModule) setFlag(v *varState, val cty.Value) error {
	if v.ty != cty.DynamicPseudoType && val.IsWhollyKnown() && m.chargeConversion(v, val) {
		converted, err := v.convert(val)
		if err != nil {
			return fmt.Errorf("--var %q: not a valid %s", v.Name, typeexpr.TypeString(v.ty))
		}
		val = converted
	}
	v.set(val, hcl.Range{})
	return nil
}

// chargeConversion charges the module's function work for applying v's optional-attribute
// defaults to val and converting it to v's type constraint, which unify element types in
// quadratic time where the constraint holds a collection type (ADR 0029), and reports whether
// it fit.
func (m *ParsedModule) chargeConversion(v *varState, val cty.Value) bool {
	if !typeHasCollection(v.ty) {
		return true
	}
	cost, done := conversionCostDone(val, v.ty, v.defaults != nil, maxFunctionWork-m.fnWork)
	if v.defaults != nil && cost <= maxFunctionWork-m.fnWork {
		cost = min(cost+defaultsGrowthCost(val, v.ty, v.defaults), maxFunctionWork+1)
	}
	if cost == 0 || m.chargeFunctionWork(cost) {
		return true
	}
	// A refusal spends only the work the estimate did (converting and hashing elements to
	// build sets), not the estimate: a variable is converted once per module instance, so a
	// refused one cannot repeat, and spending the estimate would refuse every later variable,
	// even an unrelated one; but the work done must count, or many variables would each do a
	// module's worth (T-0116 review).
	m.spendFunctionWork(done)
	return false
}

// defaultsGrowthCost bounds what applying defaults adds to converting val to ty, which the
// conversion estimate, made on val before defaults, cannot see (T-0116l): typeexpr inserts the
// default values into every object that lacks them, and applies the child defaults to the
// inserted values in turn, so each of val's objects can gain at most what the type's defaults
// can insert into one object (insertedWeight). Each inserted value is walked, and its sets sorted, as
// valueSizeWalk charges a walk (ADR 0036). When ty holds a set whose elements hold sets, the
// outer set's first sort also pays, per level, each element's inserted size and nestedSortFactor
// times its inserted sorts, since every comparison hashes both elements: one walk of 300 objects
// that each gained a 200-string set took 4.1 s.
func defaultsGrowthCost(val cty.Value, ty cty.Type, d *typeexpr.Defaults) int {
	size, sort := insertedWeight(d)
	if size == 0 {
		return 0
	}
	k := objectCount(val, maxFunctionWork/max(size+sort, 1)+1)
	cost := saturatingMul(k, size+sort)
	if typeHasNestedSet(ty) {
		per := min(size+saturatingMul(nestedSortFactor, sort), maxFunctionWork+1)
		cost = min(cost+saturatingMul(saturatingMul(bits.Len(uint(k)), k), per), maxFunctionWork+1)
	}
	return cost
}

// insertedWeight bounds the size and walk sort (valueSizeWalk) of what applying the defaults d
// can insert into any one object. An object takes the defaults of the one node of d's tree its
// place in the value matches, so the bound is the largest of the nodes' insertions (each
// component taken at its largest). A node inserts each of its default values, which typeexpr
// grows in turn by applying the child defaults to it (Defaults.apply:
// Children[key].apply(default)): so a default counts its own size, plus its objects times the
// most the child's subtree can insert into one object. Each node is computed once (memo), so the
// work is linear in the tree (computing a child for each of its uses doubled the work per
// level, T-0116l review), and a chain of nested optional objects costs about its depth, while
// defaults that hold many objects with defaults multiply. It saturates past maxFunctionWork.
func insertedWeight(d *typeexpr.Defaults) (size, sort int) {
	w := defaultsWeights{}.most(d)
	return w[0], w[1]
}

// defaultsWeights memoizes insertedWeight by node.
type defaultsWeights map[*typeexpr.Defaults][2]int

// most is the most d's subtree can insert into one object, as {size, sort}.
func (memo defaultsWeights) most(d *typeexpr.Defaults) [2]int {
	if d == nil {
		return [2]int{}
	}
	if w, ok := memo[d]; ok {
		return w
	}
	var most, own [2]int
	for _, key := range slices.Sorted(maps.Keys(d.Children)) {
		c := memo.most(d.Children[key])
		most = [2]int{max(most[0], c[0]), max(most[1], c[1])}
	}
	for _, key := range slices.Sorted(maps.Keys(d.DefaultValues)) {
		if own[0]+own[1] > maxFunctionWork {
			break
		}
		v := d.DefaultValues[key]
		n, w, _ := valueSizeWalk(v, maxFunctionWork, maxFunctionWork, maxNesting)
		if child := d.Children[key]; child != nil {
			c := memo.most(child)
			k := objectCount(v, maxFunctionWork)
			n, w = min(n+saturatingMul(k, c[0]), maxFunctionWork+1), min(w+saturatingMul(k, c[1]), maxFunctionWork+1)
		}
		own = [2]int{min(own[0]+n, maxFunctionWork+1), min(own[1]+w, maxFunctionWork+1)}
	}
	most = [2]int{max(most[0], own[0]), max(most[1], own[1])}
	memo[d] = most
	return most
}

// objectCount counts the objects and maps in v, which typeexpr may insert defaults into, up to
// limit. v is a value before conversion, already measured.
func objectCount(v cty.Value, limit int) int {
	n := 0
	stack := []cty.Value{v}
	for len(stack) > 0 && n <= limit {
		val, _ := stack[len(stack)-1].Unmark()
		stack = stack[:len(stack)-1]
		if !val.IsKnown() || val.IsNull() || !val.CanIterateElements() {
			continue
		}
		if ty := val.Type(); ty.IsObjectType() || ty.IsMapType() {
			n++
		}
		for it := val.ElementIterator(); it.Next(); {
			_, e := it.Element()
			stack = append(stack, e)
		}
	}
	return n
}

// typeHasNestedSet reports whether ty holds a set whose element type holds a set.
func typeHasNestedSet(ty cty.Type) bool {
	switch {
	case ty.IsSetType():
		return typeHasSet(ty.ElementType()) || typeHasNestedSet(ty.ElementType())
	case ty.IsListType() || ty.IsMapType():
		return typeHasNestedSet(ty.ElementType())
	case ty.IsObjectType():
		for _, at := range ty.AttributeTypes() {
			if typeHasNestedSet(at) {
				return true
			}
		}
	case ty.IsTupleType():
		for _, et := range ty.TupleElementTypes() {
			if typeHasNestedSet(et) {
				return true
			}
		}
	}
	return false
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
		if !m.chargeConversion(v, val) {
			m.diag(SeverityWarning, DiagValueTooLarge, "Variable value too large to convert",
				fmt.Sprintf("Converting the value of variable %q to %s would take too long, so it is unknown.", v.Name, out.Type),
				v.from.Filename, v.from.Start.Line, v.from.Start.Column)
			out.Value = cty.UnknownVal(v.ty).WithMarks(marks)
			break
		}
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

// chargeOptionalDefaults charges, before typeexpr runs, what typeexpr does with the optional()
// defaults in the type expression expr: it evaluates each default without a context and
// converts it to its attribute's type, outside iace's charges (T-0116k: a 100 × 200
// set(set(string)) default took 6.3 s to declare). It walks expr as typeexpr does (hcl.ExprCall,
// ExprMap, ExprList, so .tf.json types too) and charges each default (chargeDefault). It
// reports false, having spent the work done, when a default is refused or does not fit. Invalid
// types are left to typeexpr, which reports them.
func (m *ParsedModule) chargeOptionalDefaults(expr hcl.Expression) bool {
	call, diags := hcl.ExprCall(expr)
	if diags.HasErrors() {
		return true // a keyword, or not a type: typeexpr reads or reports it
	}
	switch {
	case len(call.Arguments) != 1:
		return true
	case call.Name == "list" || call.Name == "set" || call.Name == "map":
		return m.chargeOptionalDefaults(call.Arguments[0])
	case call.Name == "tuple":
		elems, diags := hcl.ExprList(call.Arguments[0])
		if diags.HasErrors() {
			return true
		}
		for _, e := range elems {
			if !m.chargeOptionalDefaults(e) {
				return false
			}
		}
	case call.Name == "object":
		attrs, diags := hcl.ExprMap(call.Arguments[0])
		if diags.HasErrors() {
			return true
		}
		for _, attr := range attrs {
			aty := attr.Value
			if opt, diags := hcl.ExprCall(aty); !diags.HasErrors() && opt.Name == "optional" && len(opt.Arguments) > 0 {
				aty = opt.Arguments[0]
				if !m.chargeOptionalDefaults(aty) {
					return false
				}
				if len(opt.Arguments) == 2 && !m.chargeDefault(aty, opt.Arguments[1]) {
					return false
				}
				continue
			}
			if !m.chargeOptionalDefaults(aty) {
				return false
			}
		}
	}
	return true
}

// chargeDefault charges evaluating the optional() default def twice (here, then typeexpr) and
// converting it to the type tyExpr reads as (chargeOptionalDefaults). Only a static literal
// default (staticLiteral) is accepted: it evaluates in linear time, charged twice its size. Any
// other is refused. Evaluating it could unify or compare uncharged (a .tf.json type string is
// not one of the module's sources, so evalExpr cannot evaluate it), and typeexpr cannot evaluate
// a native one, whose conditionals and comparisons iace rewrote into its own functions: the
// defaults were dropped without a word.
func (m *ParsedModule) chargeDefault(tyExpr, def hcl.Expression) bool {
	se, ok := def.(hclsyntax.Expression)
	if !ok || !staticLiteral(se) {
		return false
	}
	val, diags := def.Value(nil)
	if diags.HasErrors() {
		return true // typeexpr reports the default as invalid, converting nothing
	}
	// Measuring it walks it once more; a walk stopped early has not counted all of it.
	n, measured := valueSize(val, maxFunctionWork, maxNesting)
	evaluated := saturatingMul(2, n)
	if !measured || !m.canChargeFunctionWork(evaluated) {
		m.spendFunctionWork(n) // the evaluation and the walk done
		return false
	}
	// TypeConstraint reads the type without evaluating defaults; a nested optional() with a
	// default is an error there, but the type it returns is the one typeexpr converts to.
	ty, _ := typeexpr.TypeConstraint(tyExpr)
	cost, done := conversionCostDone(val, ty, false, m.workLeft()-evaluated)
	if m.chargeFunctionWork(evaluated, cost) {
		return true
	}
	m.spendFunctionWork(min(done+n, maxFunctionWork+1)) // the estimate, and the evaluation done
	return false
}

// staticLiteral reports whether e is built only of literal values, negations, parentheses,
// tuples, objects with literal or bare-word keys, and templates without interpolations:
// evaluating it is linear in its source, with no unification or comparison.
func staticLiteral(e hclsyntax.Expression) bool {
	stack := []hclsyntax.Expression{e}
	for len(stack) > 0 {
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch e := e.(type) {
		case *hclsyntax.LiteralValueExpr:
		case *hclsyntax.TupleConsExpr:
			stack = append(stack, e.Exprs...)
		case *hclsyntax.ObjectConsExpr:
			for _, item := range e.Items {
				stack = append(stack, item.KeyExpr, item.ValueExpr)
			}
		case *hclsyntax.ObjectConsKeyExpr:
			if _, bare := e.Wrapped.(*hclsyntax.ScopeTraversalExpr); bare && !e.ForceNonLiteral && hcl.ExprAsKeyword(e.Wrapped) != "" {
				continue
			}
			stack = append(stack, e.Wrapped)
		case *hclsyntax.UnaryOpExpr: // -1, !true
			stack = append(stack, e.Val)
		case *hclsyntax.ParenthesesExpr:
			stack = append(stack, e.Expression)
		case *hclsyntax.TemplateExpr:
			for _, part := range e.Parts {
				if _, ok := part.(*hclsyntax.LiteralValueExpr); !ok {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// safeTypeExpr checks a type expression before typeexpr walks it. In .tf.json a type is a string
// that hcl parses as an expression, so each string is lexed and checked like an expression.
func (m *ParsedModule) safeTypeExpr(expr hcl.Expression) bool {
	r := expr.Range()
	if !strings.HasSuffix(r.Filename, ".json") {
		// typeexpr evaluates optional() defaults itself, so a for expression there would not
		// be charged (ADR 0020): a type with one is refused.
		se, ok := expr.(hclsyntax.Expression)
		return m.safeToEvaluate(expr) && (!ok || !hasForExpr(se))
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
			if e, diags := hclsyntax.ParseExpression([]byte(tok.String()), r.Filename, hcl.InitialPos); !diags.HasErrors() && hasForExpr(e) {
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
