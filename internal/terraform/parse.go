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

	// src holds each file's bytes, so expressions can be checked before evaluation.
	src map[string][]byte
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
// that cannot be read (removed, grown past the limit) or a cancelled context is an error.
func ParseModule(ctx context.Context, root *fsutil.Root, dir Dir, limits Limits) (*ParsedModule, error) {
	m := &ParsedModule{Dir: dir.Path}
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
	if m.src == nil {
		m.src = map[string][]byte{}
	}
	m.src[name] = data
	if err := checkNesting(name, data); err != nil {
		line := 0
		if ne, ok := errors.AsType[*nestingError](err); ok {
			line = ne.line
		}
		m.diag(SeverityError, DiagNestingTooDeep, "Nesting too deep",
			"The file nests expressions or blocks too deeply to parse safely, so it was not parsed.", name, line, 0)
		return
	}
	var file *hcl.File
	var diags hcl.Diagnostics
	if strings.HasSuffix(name, ".json") {
		file, diags = parser.ParseJSON(data, name)
	} else {
		file, diags = parser.ParseHCL(data, name)
	}
	m.addHCLDiags(name, diags)
	if file == nil || diags.HasErrors() {
		// Terraform rejects the file, so its blocks are not used: a truncated body would yield
		// misleading values. The error makes the module a parse_error gap.
		return
	}

	content, remain, diags := file.Body.PartialContent(topLevelSchema)
	m.addHCLDiags(name, diags)
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
			m.diag(SeverityError, DiagSyntax, "Unsupported argument",
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
	m.diag(SeverityWarning, DiagUnsupportedBlock, "Unsupported block type",
		fmt.Sprintf("Blocks of type %q are not supported by iace, so this block is not checked.", blockType),
		name, r.Start.Line, r.Start.Column)
}

func (m *ParsedModule) addHCLDiags(name string, diags hcl.Diagnostics) {
	for _, d := range diags {
		sev := SeverityError
		if d.Severity == hcl.DiagWarning {
			sev = SeverityWarning
		}
		line, col := 0, 0
		if d.Subject != nil {
			line, col = d.Subject.Start.Line, d.Subject.Start.Column
		}
		// hcl's Detail can quote source text, such as an unquoted value ("x" is not a valid JSON
		// keyword), so only its Summary, which names keywords and blocks, is kept.
		m.diag(sev, DiagSyntax, d.Summary, "", name, line, col)
	}
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
