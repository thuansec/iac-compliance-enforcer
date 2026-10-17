package terraform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// TestEveryDiagnosticCodeHasAGapKind reads every DiagCode constant from the package source and
// fails when one is missing from diagGapKinds, so a new diagnostic cannot be dropped (ADR 0046).
func TestEveryDiagnosticCodeHasAGapKind(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var codes []DiagCode
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "DiagCode" {
					// A code written another way (DiagCode("x"), or untyped) must not be missed.
					for _, n := range vs.Names {
						if strings.HasPrefix(n.Name, "Diag") {
							t.Errorf("%s: constant %s is not declared with type DiagCode", fset.Position(n.Pos()), n.Name)
						}
					}
					continue
				}
				for _, v := range vs.Values {
					lit, ok := v.(*ast.BasicLit)
					if !ok {
						t.Fatalf("%s: a DiagCode constant that is not a string literal", fset.Position(v.Pos()))
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					codes = append(codes, DiagCode(s))
				}
			}
		}
	}
	if len(codes) < 39 {
		t.Fatalf("found %d DiagCode constants, want at least the 39 known in T-0109d", len(codes))
	}
	for _, c := range codes {
		if _, ok := diagGapKinds[c]; !ok {
			t.Errorf("diagnostic code %q has no gap kind in diagGapKinds", c)
		}
	}
	for c := range diagGapKinds {
		if !slices.Contains(codes, c) {
			t.Errorf("diagGapKinds maps %q, which is no DiagCode constant", c)
		}
	}
}

func TestDiagnosticGaps(t *testing.T) {
	for _, tc := range []struct {
		d    Diagnostic
		kind model.GapKind
	}{
		{Diagnostic{Severity: SeverityError, Code: DiagUnsupportedFunction}, model.GapParseError},
		{Diagnostic{Severity: SeverityWarning, Code: DiagUnsupportedFunction}, model.GapUnsupportedFunction},
		{Diagnostic{Severity: SeverityWarning, Code: DiagModuleUnresolved}, model.GapUnresolvedModule},
		{Diagnostic{Severity: SeverityWarning, Code: DiagModuleWorkLimit}, model.GapLimitExceeded},
		{Diagnostic{Severity: SeverityWarning, Code: DiagReferencesIncomplete}, model.GapIncompleteReferences},
		{Diagnostic{Severity: SeverityWarning, Code: DiagUninstantiatedModule}, model.GapIncompleteAnalysis},
		{Diagnostic{Severity: SeverityWarning, Code: "a_future_code"}, model.GapIncompleteAnalysis},
	} {
		g := diagnosticGap(tc.d)
		if g.Kind != tc.kind {
			t.Errorf("%s %s: kind %s, want %s", tc.d.Severity, tc.d.Code, g.Kind, tc.kind)
		}
		if !strings.Contains(g.Detail, string(tc.d.Code)) {
			t.Errorf("%s: detail %q does not name the code", tc.d.Code, g.Detail)
		}
	}
}

func TestSkipGaps(t *testing.T) {
	for reason, kind := range map[SkipReason]model.GapKind{
		SkipTooLarge:      model.GapLimitExceeded,
		SkipFileLimit:     model.GapLimitExceeded,
		SkipSymlinkEscape: model.GapSkippedFile,
		SkipSymlinkDir:    model.GapSkippedFile,
		SkipNotRegular:    model.GapSkippedFile,
		"a_future_reason": model.GapSkippedFile,
	} {
		g := skipGap(Skip{Path: "a/b.tf", Reason: reason})
		if g.Kind != kind || g.File != "a/b.tf" || !strings.Contains(g.Detail, string(reason)) {
			t.Errorf("%s: gap %+v, want kind %s on a/b.tf naming the reason", reason, g, kind)
		}
	}
}

func TestSkipOwner(t *testing.T) {
	roots := []string{".", "infra", "infra/prod"}
	for path, want := range map[string]int{
		"main.tf":                0,
		"infra/x.tf":             1,
		"infra/prod/big.tf":      2,
		"infra/prod/sub/link.tf": 2,
		"infrastructure/x.tf":    0,
	} {
		if got := skipOwner(roots, path); got != want {
			t.Errorf("%s: owner %d, want %d", path, got, want)
		}
	}
	if got := skipOwner([]string{"a", "b"}, "c/x.tf"); got != 0 {
		t.Errorf("unowned skip: owner %d, want the first document", got)
	}
}

func TestUnexpressedGaps(t *testing.T) {
	doc := &model.InputDocument{
		Resources: []model.Resource{
			{Address: "x.a", Source: model.ResourceSource{File: "main.tf", Range: model.Range{StartLine: 3}}},
			{Address: "module.m.x.b", Source: model.ResourceSource{File: "m/main.tf", Range: model.Range{StartLine: 7}}},
		},
		Outputs: []model.Output{
			{Name: "o", Module: "module.m", SourceRange: model.SourceLocation{File: "m/out.tf", Range: model.Range{StartLine: 2}}},
		},
	}
	un := Unexpressed{
		IncompleteResources:  []string{"module.m.x.b"},
		IncompleteReferences: []string{"module.m.output.o", "x.a"},
	}
	var got []string
	for _, g := range unexpressedGaps(doc, un) {
		got = append(got, string(g.Kind)+" "+g.File+":"+strconv.Itoa(g.Line)+" "+g.Detail)
	}
	want := []string{
		"incomplete_analysis m/main.tf:7 values of module.m.x.b cannot be expressed as paths (ADR 0045)",
		"incomplete_references m/out.tf:2 references of module.m.output.o may be incomplete",
		"incomplete_references main.tf:3 references of x.a may be incomplete",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestTreeGaps(t *testing.T) {
	rr := RootResult{
		Dir: "infra",
		Tree: &ModuleTree{
			Root: &ModuleNode{Module: &ParsedModule{
				Blocks:      []Block{{Type: "resource", File: "infra/main.tf"}},
				Diagnostics: []Diagnostic{{Severity: SeverityWarning, Code: DiagUnsupportedBlock, Summary: "Unsupported block", File: "infra/main.tf", Line: 4}},
			}},
			Skipped:   []Skip{{Path: "infra/modules/link", Reason: SkipSymlinkDir}},
			Truncated: true,
		},
	}
	docs := Documents(nil, []RootResult{rr})
	var got []string
	for _, g := range docs[0].CoverageGaps {
		got = append(got, string(g.Kind)+" "+g.File+":"+strconv.Itoa(g.Line))
	}
	want := []string{
		"limit_exceeded infra/main.tf:0",
		"incomplete_analysis infra/main.tf:4",
		"skipped_file infra/modules/link:0",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if empty := Documents(nil, []RootResult{{Dir: "."}}); len(empty[0].CoverageGaps) != 0 {
		t.Errorf("gaps %v for an empty root, want none", empty[0].CoverageGaps)
	}
}
