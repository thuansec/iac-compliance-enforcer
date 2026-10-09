package terraform

import (
	"errors"
	"io/fs"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// Diagnostic codes for the filesystem functions.
const (
	// DiagFileOutsideModule: file, fileexists or templatefile named a path outside the scan
	// root (absolute, home-relative or with too many ".."), which iace does not read, so the
	// call is unknown.
	DiagFileOutsideModule DiagCode = "file_outside_module"
	// DiagFileUnreadable: the named file is missing, too large, not a regular file, not UTF-8
	// text, or reached through a symlink that leaves the scan root, so the call is unknown.
	DiagFileUnreadable DiagCode = "file_unreadable"
	// DiagTemplateError: a templatefile template could not be parsed or evaluated (a syntax
	// error, a variable that is not in its vars, a nested templatefile), so the call is unknown.
	DiagTemplateError DiagCode = "template_error"
)

// maxFunctionFileSize bounds the files that file and templatefile read. The result is then
// bounded like any function result, so a file that large is read but unknown.
const maxFunctionFileSize = 1 << 20

// fileCallCost is the work charged for each filesystem call (resolving the path through the
// scan root and a stat or a read), before it happens, so that calls stop touching the
// filesystem once the module's function work is spent.
const fileCallCost = 1 << 10

// moduleFunctionNames are the functions built per module, because they read the module's files
// or charge its function work themselves: fileFunctions, replaceFunc and regexFunc.
var moduleFunctionNames = []string{"file", "fileexists", "regex", "regexall", "replace", "templatefile"}

// pendingDiag is a warning a function call raised, reported at the evaluated expression.
type pendingDiag struct {
	code            DiagCode
	summary, detail string
}

// fnWarn records a warning for the expression being evaluated.
func (m *ParsedModule) fnWarn(code DiagCode, summary, detail string) {
	m.fnDiags = append(m.fnDiags, pendingDiag{code: code, summary: summary, detail: detail})
}

// fileFunctions returns file, fileexists and templatefile for this module instance. Relative
// paths resolve against the root module's directory, Terraform's working directory, which is the
// module's own directory for a root module; path.module locates the module from there (T-0107f,
// ADR 0015). They read only inside the scan root, through it, so neither ".." nor a symlink can
// leave it. Anything they cannot read is unknown with a warning, never an error.
func (m *ParsedModule) fileFunctions() map[string]function.Function {
	file := function.New(&function.Spec{
		Description: "Reads a UTF-8 text file, relative to the root module directory.",
		Params:      []function.Parameter{{Name: "path", Type: cty.String}},
		Type:        function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			data, ok := m.readModuleFile(args[0].AsString())
			if !ok {
				return cty.UnknownVal(cty.String), nil
			}
			return cty.StringVal(string(data)), nil
		},
	})
	fileExists := function.New(&function.Spec{
		Description: "Reports whether a regular file exists, relative to the root module directory.",
		Params:      []function.Parameter{{Name: "path", Type: cty.String}},
		Type:        function.StaticReturnType(cty.Bool),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			return m.moduleFileExists(args[0].AsString()), nil
		},
	})
	templateFile := function.New(&function.Spec{
		Description: "Renders a template file, relative to the root module directory, with the given variables.",
		Params: []function.Parameter{
			{Name: "path", Type: cty.String},
			{Name: "vars", Type: cty.DynamicPseudoType},
		},
		Type: func(args []cty.Value) (cty.Type, error) {
			ty := args[1].Type()
			if !ty.IsMapType() && !ty.IsObjectType() && ty != cty.DynamicPseudoType {
				return cty.NilType, function.NewArgErrorf(1, "vars must be a map or an object")
			}
			return cty.String, nil
		},
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			vars, err := templateVars(args[1])
			if err != nil {
				return cty.NilVal, err
			}
			if vars == nil {
				return cty.UnknownVal(cty.String), nil
			}
			return m.renderTemplate(args[0].AsString(), vars), nil
		},
	})
	return map[string]function.Function{"file": file, "fileexists": fileExists, "templatefile": templateFile}
}

// filePath resolves p, a path from a function argument, against the instance's base directory:
// the root module's directory, which is Terraform's working directory for every module of a
// tree. It refuses absolute, home-relative and drive-letter paths and paths that leave the scan
// root; the scan root confines symlinks on the read itself.
func (m *ParsedModule) filePath(p string) (string, bool) {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) || strings.HasPrefix(p, "~") ||
		len(p) >= 2 && p[1] == ':' {
		return "", false
	}
	c := path.Join(m.base(), p)
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", false
	}
	return c, true
}

// base is the directory relative file paths resolve against: the root module's directory.
func (m *ParsedModule) base() string {
	if m.baseDir != "" {
		return m.baseDir
	}
	return m.Dir
}

// readModuleFile reads the UTF-8 text file p (filePath), charging its size to the module's
// function work. It reports a warning and false when it cannot.
func (m *ParsedModule) readModuleFile(p string) ([]byte, bool) {
	name, ok := m.filePath(p)
	if !ok {
		m.fnWarn(DiagFileOutsideModule, "File outside the scan root",
			"The path is absolute or leaves the scan root, which iace does not read, so the value is unknown.")
		return nil, false
	}
	if m.root == nil {
		m.fnWarn(DiagFileUnreadable, "File not readable", "No scan root is open, so the value is unknown.")
		return nil, false
	}
	if !m.chargeFunctionWork(fileCallCost) {
		m.fnLimited = true
		return nil, false
	}
	// Read no more than the work left: fsutil refuses a larger file by its size, before reading.
	limit := min(maxFunctionFileSize, maxFunctionWork-m.fnWork)
	data, err := m.root.ReadFile(name, int64(limit))
	m.fileBytesRead += len(data)
	switch {
	case errors.Is(err, fsutil.ErrTooLarge) && limit < maxFunctionFileSize:
		m.fnLimited = true
		return nil, false
	case err != nil:
		m.fnWarn(DiagFileUnreadable, "File not readable",
			"The file is missing, larger than 1 MiB, not a regular file, or reached through a symlink that leaves the scan root, so the value is unknown.")
		return nil, false
	case !m.chargeFunctionWork(len(data)): // every byte read is charged, whatever follows
		m.fnLimited = true
		return nil, false
	case !utf8.Valid(data):
		m.fnWarn(DiagFileUnreadable, "File not UTF-8 text", "The file is not UTF-8 text, so the value is unknown.")
		return nil, false
	}
	return data, true
}

// moduleFileExists reports whether p (filePath) is a regular file: false when nothing is there,
// and unknown with a warning when p is outside the scan root, is something other than a regular
// file, or cannot be checked.
func (m *ParsedModule) moduleFileExists(p string) cty.Value {
	name, ok := m.filePath(p)
	if !ok {
		m.fnWarn(DiagFileOutsideModule, "File outside the scan root",
			"The path is absolute or leaves the scan root, which iace does not read, so the value is unknown.")
		return cty.UnknownVal(cty.Bool)
	}
	unreadable := func() cty.Value {
		m.fnWarn(DiagFileUnreadable, "File not checkable",
			"The path is not a regular file, or could not be checked inside the scan root, so the value is unknown.")
		return cty.UnknownVal(cty.Bool)
	}
	if m.root == nil {
		return unreadable()
	}
	if !m.chargeFunctionWork(fileCallCost) {
		m.fnLimited = true
		return cty.UnknownVal(cty.Bool)
	}
	fi, err := m.root.Stat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return cty.False
	case err != nil || !fi.Mode().IsRegular():
		return unreadable()
	}
	return cty.True
}

// templateVars returns the template variables in vars, which must be a map or object whose
// keys are identifiers. It returns nil when vars is not wholly known.
func templateVars(vars cty.Value) (map[string]cty.Value, error) {
	if !vars.IsWhollyKnown() {
		return nil, nil
	}
	out := map[string]cty.Value{}
	for it := vars.ElementIterator(); it.Next(); {
		k, v := it.Element()
		name := k.AsString()
		if !hclsyntax.ValidIdentifier(name) {
			return nil, function.NewArgErrorf(1, "vars keys must be valid identifiers")
		}
		out[name] = v
	}
	return out, nil
}

// renderTemplate renders the template file p with vars, under the same guards and function table
// as any expression, except that templatefile cannot be called from inside a template. A problem
// in the template is reported at the template file and makes the result unknown.
func (m *ParsedModule) renderTemplate(p string, vars map[string]cty.Value) cty.Value {
	unknown := cty.UnknownVal(cty.String)
	src, ok := m.readModuleFile(p)
	if !ok {
		return unknown
	}
	name, _ := m.filePath(p)
	tokens, _ := hclsyntax.LexTemplate(src, name, hcl.InitialPos)
	if scanTokens(tokens, maxOperators) != nil {
		m.diag(SeverityWarning, DiagExpressionTooComplex, "Expression too complex",
			"The template is nested too deeply, or has too many operators or chained steps, to evaluate safely, so its value is unknown.",
			name, 0, 0)
		return unknown
	}
	templateError := func(diags hcl.Diagnostics) cty.Value {
		line, col := 0, 0
		if s := diags[0].Subject; s != nil {
			line, col = s.Start.Line, s.Start.Column
		}
		m.diag(SeverityWarning, DiagTemplateError, diags[0].Summary,
			"The template could not be evaluated, so its value is unknown.", name, line, col)
		return unknown
	}
	expr, diags := hclsyntax.ParseTemplate(src, name, hcl.InitialPos)
	if diags.HasErrors() {
		return templateError(errorsOnly(diags))
	}
	fns := map[string]function.Function{}
	for n, f := range m.functions(expr, syntaxCalls(expr)) {
		fns[n] = f
	}
	for _, n := range []string{"templatefile", "core::templatefile"} {
		fns[n] = nestedTemplateFunc
	}
	val, diags := expr.Value(&hcl.EvalContext{Variables: vars, Functions: fns})
	if diags.HasErrors() {
		return templateError(errorsOnly(diags))
	}
	str, err := convert.Convert(val, cty.String)
	if err != nil {
		return templateError(hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "Template result is not a string"}})
	}
	return str
}

// nestedTemplateFunc replaces templatefile inside a template: Terraform rejects the call.
var nestedTemplateFunc = function.New(&function.Spec{
	Description: "templatefile cannot be called from inside a template.",
	VarParam:    &function.Parameter{Name: "args", Type: cty.DynamicPseudoType, AllowNull: true, AllowUnknown: true, AllowDynamicType: true},
	Type:        function.StaticReturnType(cty.String),
	Impl: func([]cty.Value, cty.Type) (cty.Value, error) {
		return cty.NilVal, errors.New("templatefile cannot be called from inside a template")
	},
})

// errorsOnly returns the error diagnostics in diags.
func errorsOnly(diags hcl.Diagnostics) hcl.Diagnostics {
	var out hcl.Diagnostics
	for _, d := range diags {
		if d.Severity == hcl.DiagError {
			out = append(out, d)
		}
	}
	return out
}
