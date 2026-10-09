package terraform

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty/function"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// Severity of a parse diagnostic.
type Severity string

// Severities.
const (
	// SeverityError means Terraform itself would reject the file; the module is a parse_error gap.
	SeverityError Severity = "error"
	// SeverityWarning means part of the file is not checked, but the rest is.
	SeverityWarning Severity = "warning"
)

// DiagCode classifies a parse diagnostic.
type DiagCode string

// Diagnostic codes.
const (
	// DiagSyntax: an HCL or JSON syntax or structure error reported by the parser.
	DiagSyntax DiagCode = "syntax"
	// DiagNestingTooDeep: the file nests too deeply to parse safely and was not parsed.
	DiagNestingTooDeep DiagCode = "nesting_too_deep"
	// DiagOverrideNotMerged: an override file, whose settings are not merged yet and not checked.
	DiagOverrideNotMerged DiagCode = "override_not_merged"
	// DiagUnsupportedBlock: a top-level block type iace does not know (a newer Terraform
	// feature, for example); it is not checked.
	DiagUnsupportedBlock DiagCode = "unsupported_block"
	// DiagExpressionTooComplex: an expression was nested too deeply or had too many operators to
	// evaluate safely, so its value is unknown. It is a limit_exceeded coverage gap.
	DiagExpressionTooComplex DiagCode = "expression_too_complex"
)

// Diagnostic is a structured parse problem located in a file relative to the scan root. Line
// and Column are 1-based, or 0 when the problem concerns the whole file.
type Diagnostic struct {
	Severity Severity
	Code     DiagCode
	Summary  string
	// Detail is iace-authored text, or empty. It never contains source content, which may hold
	// secrets.
	Detail string
	File   string
	Line   int
	Column int
}

// String returns `"file":line:column: severity: summary`. The file name comes from the scanned
// repository, so it is quoted.
func (d Diagnostic) String() string {
	return fmt.Sprintf("%q:%d:%d: %s: %s", d.File, d.Line, d.Column, d.Severity, d.Summary)
}

// Block is one top-level block of a module, such as a resource or a variable.
type Block struct {
	Type   string
	Labels []string
	// File is relative to the scan root.
	File string
	// Range spans the whole block; DefRange is its header (type and labels).
	Range    hcl.Range
	DefRange hcl.Range
	// Body is the block's content, decoded by later stages.
	Body hcl.Body
}

// ParsedModule is the syntax of one module directory.
type ParsedModule struct {
	Dir string
	// Blocks are in file order, then in source order within a file.
	Blocks []Block
	// Diagnostics are sorted by file, line, column, code and summary, without duplicates.
	Diagnostics []Diagnostic

	// src holds each file's bytes, so expressions can be checked before evaluation. Set and
	// remove entries with setSource and dropSource, which keep inspected in step.
	src map[string][]byte
	// inspected memoizes inspectExpr per file by source range, so each expression is lexed and
	// checked once however often it is evaluated or inspected.
	inspected map[string]map[[2]int]inspection
	// root is the scan root the module was read from, which the filesystem functions read
	// through; nil means they read nothing.
	root *fsutil.Root

	// fns is the bounded function table, built at the first evaluation that calls a function;
	// unsupportedSeen holds the unsupported function names already reported.
	fns             map[string]function.Function
	unsupportedSeen map[string]bool
	// fnWork is the work charged to function calls so far, at most maxFunctionWork; fnLimited
	// records that a call during the current evaluation was over a function limit, and
	// fnDiags the warnings its calls raised.
	fnWork    int
	fnLimited bool
	fnDiags   []pendingDiag
	// fileBytesRead counts the bytes the filesystem functions read, which never pass the work
	// they were charged.
	fileBytesRead int
	// parseDiagCounts counts the parse diagnostics of each file; tooManyErrors records the
	// files whose too_many_diagnostics entry is an error (parseDiag).
	parseDiagCounts map[string]int
	tooManyErrors   map[string]bool
	// budget is the scan's parse budget (Limits.ParseBudget), nil for none.
	budget *ParseBudget
	// required memoizes RequiredProviders.
	required map[string]RequiredProvider
	// addrPrefix is the instance's module address ("module.a[0]"), which qualifies the
	// addresses it records; empty for a root module.
	addrPrefix string
	// attrRefs counts the reference entries recorded for resources, outputs and module inputs,
	// at most maxReferenceEntries; refsWarned records its warning.
	attrRefs   int
	refsWarned bool
	// baseDir is the directory relative file paths resolve against and pathModule is
	// path.module, for a child module instance (EvaluateTree); empty means the module is its own
	// root: its directory and ".".
	baseDir, pathModule string
	// usage records what the last evaluation of locals and of resources used of their budgets,
	// what all module inputs used together, and the unknown path steps of every evaluation
	// (which accumulate, so a repeated evaluation over-counts and fails closed). EvaluateTree
	// charges it to the tree.
	usage moduleUsage
	// regexes caches the module's regular expressions by pattern.
	regexes map[string]*regexEntry
	// lastRegex is the last pattern parsed past the cache, with its pattern.
	lastRegex        *regexEntry
	lastRegexPattern string
}

// HasErrors reports whether any diagnostic is an error.
func (m *ParsedModule) HasErrors() bool {
	return slices.ContainsFunc(m.Diagnostics, func(d Diagnostic) bool { return d.Severity == SeverityError })
}

// topLevelSchema lists the top-level blocks Terraform accepts, with their labels.
var topLevelSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "terraform"},
		{Type: "provider", LabelNames: []string{"name"}},
		{Type: "variable", LabelNames: []string{"name"}},
		{Type: "locals"},
		{Type: "output", LabelNames: []string{"name"}},
		{Type: "module", LabelNames: []string{"name"}},
		{Type: "resource", LabelNames: []string{"type", "name"}},
		{Type: "data", LabelNames: []string{"type", "name"}},
		{Type: "ephemeral", LabelNames: []string{"type", "name"}},
		{Type: "moved"},
		{Type: "import"},
		{Type: "removed"},
		{Type: "check", LabelNames: []string{"name"}},
		{Type: "action", LabelNames: []string{"type", "name"}},
	},
}

// ParseModule parses the Terraform files of one directory with hclparse. Files are read through
// fsutil with the size limit and checked by the nesting guard first. Problems in the files become
// diagnostics, never errors. A file the parser itself rejects contributes no blocks; structural
// errors (wrong labels, top-level arguments) keep the file's valid blocks, and the module still
// HasErrors. Override files are reported, checked for syntax and nesting, and not merged. A file
// that cannot be read (removed, grown past the limit) or a cancelled context is an error. The
// module keeps root for the filesystem functions (file, fileexists, templatefile), so the caller
// keeps it open until evaluation is done; once it is closed, those calls are unknown.
func ParseModule(ctx context.Context, root *fsutil.Root, dir Dir, limits Limits) (*ParsedModule, error) {
	m := &ParsedModule{Dir: dir.Path, root: root, budget: limits.ParseBudget}
	parser := hclparse.NewParser()
	for _, name := range dir.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := root.ReadFile(name, limits.MaxFileSize)
		if err != nil {
			return nil, err
		}
		if isOverrideFile(name) {
			// Not merged (ADR 0005): reported, and still checked for syntax errors and nesting,
			// which Terraform would reject, but its blocks are not used.
			m.diag(SeverityWarning, DiagOverrideNotMerged, "Override file not merged",
				"iace does not merge override files yet, so the settings in this file are not checked.", name, 0, 0)
			n := len(m.Blocks)
			m.parseFile(parser, name, data)
			m.Blocks = m.Blocks[:n]
			continue
		}
		m.parseFile(parser, name, data)
	}
	m.sortDiagnostics()
	return m, nil
}

// sortDiagnostics restores the documented order and drops exact duplicates, which arise when
// the same expression is evaluated more than once (instances, repeated passes).
func (m *ParsedModule) sortDiagnostics() {
	slices.SortStableFunc(m.Diagnostics, func(a, b Diagnostic) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line),
			cmp.Compare(a.Column, b.Column), cmp.Compare(a.Code, b.Code), cmp.Compare(a.Summary, b.Summary),
			// Every field takes part, so equal diagnostics end up adjacent for Compact.
			cmp.Compare(a.Severity, b.Severity), cmp.Compare(a.Detail, b.Detail))
	})
	m.Diagnostics = slices.Compact(m.Diagnostics)
}

// parseFile adds one file's top-level blocks and diagnostics to the module.
func (m *ParsedModule) parseFile(parser *hclparse.Parser, name string, data []byte) {
	cost, err := lexCost(name, data)
	if err != nil {
		line := 0
		if ne, ok := errors.AsType[*nestingError](err); ok {
			line = ne.line
		}
		m.diag(SeverityError, DiagNestingTooDeep, "Nesting too deep",
			"The file nests expressions or blocks too deeply to parse safely, so it was not parsed.", name, line, 0)
		return
	}
	if !m.budget.take(cost) {
		m.diag(SeverityWarning, DiagParseLimit, "Parse budget used up",
			fmt.Sprintf("The scan already keeps the syntax of %d tokens, its limit, so this file is not parsed or checked.", m.budget.size()),
			name, 0, 0)
		return
	}
	// Only a file whose syntax is kept keeps its source, for the expression checks.
	m.setSource(name, data)
	var file *hcl.File
	var diags hcl.Diagnostics
	if strings.HasSuffix(name, ".json") {
		file, diags = parser.ParseJSON(data, name)
	} else {
		file, diags = parser.ParseHCL(data, name)
	}
	m.addParseDiags(name, diags)
	if file == nil || diags.HasErrors() {
		// Terraform rejects the file, so its blocks are not used: a truncated body would yield
		// misleading values. The error makes the module a parse_error gap.
		return
	}

	content, remain, diags := file.Body.PartialContent(topLevelSchema)
	m.addParseDiags(name, diags)
	for _, b := range content.Blocks {
		m.Blocks = append(m.Blocks, Block{
			Type: b.Type, Labels: b.Labels, File: name,
			Range: blockRange(b), DefRange: b.DefRange, Body: b.Body,
		})
	}
	m.leftovers(name, remain)
}

// leftovers reports what the top-level schema did not consume: unknown block types are
// warnings (they are not checked), attributes are errors (Terraform rejects them).
func (m *ParsedModule) leftovers(name string, remain hcl.Body) {
	if body, ok := remain.(*hclsyntax.Body); ok {
		known := map[string]bool{}
		for _, s := range topLevelSchema.Blocks {
			known[s.Type] = true
		}
		for _, b := range body.Blocks {
			if !known[b.Type] {
				m.unsupported(name, b.Type, b.TypeRange)
			}
		}
		for _, a := range body.Attributes {
			m.parseDiag(SeverityError, DiagSyntax, "Unsupported argument",
				fmt.Sprintf("An argument named %q is not expected at the top level.", a.Name), name,
				a.NameRange.Start.Line, a.NameRange.Start.Column)
		}
		return
	}
	// JSON: every key left over is a top-level name iace does not know.
	attrs, _ := remain.JustAttributes()
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		m.unsupported(name, k, attrs[k].NameRange)
	}
}

func (m *ParsedModule) unsupported(name, blockType string, r hcl.Range) {
	m.parseDiag(SeverityWarning, DiagUnsupportedBlock, "Unsupported block type",
		fmt.Sprintf("Blocks of type %q are not supported by iace, so this block is not checked.", blockType),
		name, r.Start.Line, r.Start.Column)
}

// maxDiagnosticsPerFile bounds the diagnostics parsing keeps per file: a 1 MiB file of invalid
// characters gives one per byte (118 MB), and one of empty unsupported blocks one per four bytes
// (45 MB); either would flood every report (ADR 0016).
const maxDiagnosticsPerFile = 100

// DiagTooManyDiagnostics reports a file with more parse diagnostics than iace keeps; it is an
// error when any of those not kept is one.
const DiagTooManyDiagnostics DiagCode = "too_many_diagnostics"

// markTooManyError makes file name's too_many_diagnostics entry an error.
func (m *ParsedModule) markTooManyError(name string) {
	if m.tooManyErrors == nil {
		m.tooManyErrors = map[string]bool{}
	}
	m.tooManyErrors[name] = true
	for i := range m.Diagnostics {
		if d := &m.Diagnostics[i]; d.File == name && d.Code == DiagTooManyDiagnostics {
			d.Severity = SeverityError
		}
	}
}

// parseDiag records a diagnostic that parsing file adds, at most maxDiagnosticsPerFile per file:
// a file is parsed once per module, so each one is distinct. Past the cap, one
// too_many_diagnostics diagnostic stands for the rest, with error severity once any of them is an
// error, so HasErrors never loses one. Evaluation diagnostics are not counted: they are bounded
// by the expressions evaluated, and repeated evaluations would count twice.
func (m *ParsedModule) parseDiag(sev Severity, code DiagCode, summary, detail, file string, line, col int) {
	if m.parseDiagCounts == nil {
		m.parseDiagCounts = map[string]int{}
	}
	n := m.parseDiagCounts[file]
	m.parseDiagCounts[file] = n + 1
	switch {
	case n < maxDiagnosticsPerFile:
		m.diag(sev, code, summary, detail, file, line, col)
	case n == maxDiagnosticsPerFile:
		m.diag(sev, DiagTooManyDiagnostics, "Too many diagnostics",
			fmt.Sprintf("The file has more than %d diagnostics; only the first are listed.", maxDiagnosticsPerFile),
			file, 0, 0)
		if sev == SeverityError {
			m.markTooManyError(file)
		}
	case sev == SeverityError && !m.tooManyErrors[file]:
		m.markTooManyError(file) // once per file, however many errors follow
	}
}

// addParseDiags records hcl's diagnostics from parsing file name through parseDiag.
func (m *ParsedModule) addParseDiags(name string, diags hcl.Diagnostics) {
	for _, d := range diags {
		m.parseDiag(hclSeverity(d), DiagSyntax, d.Summary, "", name, hclLine(d), hclColumn(d))
	}
}

// addHCLDiags records hcl's diagnostics for file name from evaluation, uncapped.
func (m *ParsedModule) addHCLDiags(name string, diags hcl.Diagnostics) {
	for _, d := range diags {
		// hcl's Detail can quote source text, such as an unquoted value ("x" is not a valid JSON
		// keyword), so only its Summary, which names keywords and blocks, is kept.
		m.diag(hclSeverity(d), DiagSyntax, d.Summary, "", name, hclLine(d), hclColumn(d))
	}
}

func hclSeverity(d *hcl.Diagnostic) Severity {
	if d.Severity == hcl.DiagWarning {
		return SeverityWarning
	}
	return SeverityError
}

func hclLine(d *hcl.Diagnostic) int {
	if d.Subject == nil {
		return 0
	}
	return d.Subject.Start.Line
}

func hclColumn(d *hcl.Diagnostic) int {
	if d.Subject == nil {
		return 0
	}
	return d.Subject.Start.Column
}

func (m *ParsedModule) diag(sev Severity, code DiagCode, summary, detail, file string, line, col int) {
	m.Diagnostics = append(m.Diagnostics, Diagnostic{
		Severity: sev, Code: code, Summary: summary, Detail: detail, File: file, Line: line, Column: col,
	})
}

// blockRange spans a block from its header to its closing brace.
func blockRange(b *hcl.Block) hcl.Range {
	if body, ok := b.Body.(*hclsyntax.Body); ok {
		return hcl.RangeBetween(b.DefRange, body.SrcRange)
	}
	// JSON: the body's missing-item range is its closing brace.
	return hcl.RangeBetween(b.DefRange, b.Body.MissingItemRange())
}

// isOverrideFile reports whether Terraform treats name as an override file: override.tf,
// *_override.tf and their .tf.json forms.
func isOverrideFile(name string) bool {
	base := strings.TrimSuffix(strings.TrimSuffix(path.Base(name), ".json"), ".tf")
	return base == "override" || strings.HasSuffix(base, "_override")
}
