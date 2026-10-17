package terraform

import (
	"cmp"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// diagGapKinds maps every diagnostic code to the coverage gap kind of its warnings (ADR 0046);
// an error is always a parse_error gap. A test reads every DiagCode constant of the package
// and fails when one is missing here, and diagnosticGap reports a missing one as
// incomplete_analysis, so no diagnostic is dropped.
var diagGapKinds = map[DiagCode]model.GapKind{
	DiagModuleUnresolved:    model.GapUnresolvedModule,
	DiagUnsupportedFunction: model.GapUnsupportedFunction,
	DiagUnknownExpansion:    model.GapUnknownExpansion,
	DiagInvalidExpansion:    model.GapUnknownExpansion,

	DiagExpressionTooComplex: model.GapLimitExceeded,
	DiagValueTooLarge:        model.GapLimitExceeded,
	DiagFunctionLimit:        model.GapLimitExceeded,
	DiagExpansionLimit:       model.GapLimitExceeded,
	DiagModuleWorkLimit:      model.GapLimitExceeded,
	DiagFileLimit:            model.GapLimitExceeded,
	DiagParseLimit:           model.GapLimitExceeded,
	DiagNestingTooDeep:       model.GapLimitExceeded,
	DiagTooManyDiagnostics:   model.GapLimitExceeded,

	DiagReferencesIncomplete: model.GapIncompleteReferences,

	DiagDuplicateLocal:        model.GapIncompleteAnalysis,
	DiagDuplicateModule:       model.GapIncompleteAnalysis,
	DiagDuplicateOutput:       model.GapIncompleteAnalysis,
	DiagDuplicateResource:     model.GapIncompleteAnalysis,
	DiagDuplicateVariable:     model.GapIncompleteAnalysis,
	DiagEvaluation:            model.GapIncompleteAnalysis,
	DiagFileOutsideModule:     model.GapIncompleteAnalysis,
	DiagFileUnreadable:        model.GapIncompleteAnalysis,
	DiagInvalidModuleName:     model.GapIncompleteAnalysis,
	DiagInvalidProviderSource: model.GapIncompleteAnalysis,
	DiagLocalCycle:            model.GapIncompleteAnalysis,
	DiagLockFileInvalid:       model.GapIncompleteAnalysis,
	DiagMissingModuleInput:    model.GapIncompleteAnalysis,
	DiagMissingOutputValue:    model.GapIncompleteAnalysis,
	DiagModuleCycle:           model.GapIncompleteAnalysis,
	DiagModuleManifestInvalid: model.GapIncompleteAnalysis,
	DiagOverrideUnsupported:   model.GapIncompleteAnalysis,
	DiagOverrideWithoutBase:   model.GapIncompleteAnalysis,
	DiagSyntax:                model.GapIncompleteAnalysis,
	DiagTemplateError:         model.GapIncompleteAnalysis,
	DiagUndeclaredModuleInput: model.GapIncompleteAnalysis,
	DiagUndeclaredVariable:    model.GapIncompleteAnalysis,
	DiagUninstantiatedModule:  model.GapIncompleteAnalysis,
	DiagUnsupportedBlock:      model.GapIncompleteAnalysis,
	DiagVariableType:          model.GapIncompleteAnalysis,
}

// Documents builds the input document of every evaluated root (NormalizeRoot) with its
// coverage gaps: the diagnostics of its tree and instances, its tree's skips and truncation,
// what NormalizeRoot could not express, and the discovery skips it owns (skipOwners). When
// discovery skipped files but no root remains (every Terraform file was skipped), one document
// for the scan root carries the skips, so they are never dropped.
func Documents(d *Discovery, results []RootResult) []*model.InputDocument {
	if len(results) == 0 && d != nil && len(d.Skipped) > 0 {
		results = []RootResult{{Dir: "."}}
	}
	docs := make([]*model.InputDocument, len(results))
	gaps := make([][]model.CoverageGap, len(results))
	roots := make([]string, len(results))
	loaded := make([]map[string]bool, len(results))
	for i, rr := range results {
		doc, un := NormalizeRoot(rr)
		docs[i], roots[i], loaded[i] = doc, rr.Dir, treeDirs(rr)
		gaps[i] = append(rootGaps(rr), unexpressedGaps(doc, un)...)
	}
	if d != nil {
		for _, s := range d.Skipped {
			for _, owner := range skipOwners(roots, loaded, s.Path) {
				gaps[owner] = append(gaps[owner], skipGap(s))
			}
		}
	}
	for i, doc := range docs {
		doc.CoverageGaps = sortedGaps(gaps[i])
	}
	return docs
}

// rootGaps reports the parse diagnostics of every module of the root's tree, the evaluation
// diagnostics of every instance, and the tree's skips and truncation.
func rootGaps(rr RootResult) []model.CoverageGap {
	var out []model.CoverageGap
	if rr.Tree != nil {
		for _, s := range rr.Tree.Skipped {
			out = append(out, skipGap(s))
		}
		if rr.Tree.Truncated {
			out = append(out, model.CoverageGap{
				Kind:   model.GapLimitExceeded,
				Detail: "module tree truncated: calls past the module call limit were not loaded",
				File:   treeFile(rr),
			})
		}
		// A directory's parse is shared by its nodes; report its diagnostics once.
		seen := map[*ParsedModule]bool{}
		var walk func(n *ModuleNode)
		walk = func(n *ModuleNode) {
			if n.Module != nil && !seen[n.Module] {
				seen[n.Module] = true
				for _, diag := range n.Module.Diagnostics {
					out = append(out, diagnosticGap(diag))
				}
			}
			for _, c := range n.Calls {
				if c.Child != nil {
					walk(c.Child)
				}
			}
		}
		if rr.Tree.Root != nil {
			walk(rr.Tree.Root)
		}
	}
	for _, inst := range rr.Instances {
		if inst.Module == nil {
			continue
		}
		for _, diag := range inst.Module.Diagnostics {
			out = append(out, diagnosticGap(diag))
		}
	}
	return out
}

// treeFile is the first file of the root module, where a tree-wide gap is reported, or "".
func treeFile(rr RootResult) string {
	if rr.Tree == nil || rr.Tree.Root == nil || rr.Tree.Root.Module == nil || len(rr.Tree.Root.Module.Blocks) == 0 {
		return ""
	}
	return rr.Tree.Root.Module.Blocks[0].File
}

// diagnosticGap reports a diagnostic: an error as parse_error, a warning by diagGapKinds, and
// a code missing there as incomplete_analysis. The detail names the code and repeats only
// iace-authored text, never source content.
func diagnosticGap(d Diagnostic) model.CoverageGap {
	kind, ok := diagGapKinds[d.Code]
	if !ok {
		kind = model.GapIncompleteAnalysis
	}
	if d.Severity == SeverityError {
		kind = model.GapParseError
	}
	detail := string(d.Code) + ": " + d.Summary
	if d.Detail != "" {
		detail += ": " + d.Detail
	}
	return model.CoverageGap{Kind: kind, Detail: detail, File: d.File, Line: max(d.Line, 0)}
}

// skipGap reports a file or directory that was not read: a size or count limit as
// limit_exceeded, anything else (a symlink, a file that is not regular) as skipped_file.
func skipGap(s Skip) model.CoverageGap {
	kind := model.GapSkippedFile
	if s.Reason == SkipTooLarge || s.Reason == SkipFileLimit {
		kind = model.GapLimitExceeded
	}
	detail := "skipped (" + string(s.Reason) + ")"
	if s.Detail != "" {
		detail += ": " + s.Detail
	}
	return model.CoverageGap{Kind: kind, Detail: detail, File: s.Path}
}

// treeDirs returns the module directories the root's tree loads.
func treeDirs(rr RootResult) map[string]bool {
	dirs := map[string]bool{}
	if rr.Tree == nil || rr.Tree.Root == nil {
		return dirs
	}
	var walk func(n *ModuleNode)
	walk = func(n *ModuleNode) {
		if dirs[n.Dir] {
			return
		}
		dirs[n.Dir] = true
		for _, c := range n.Calls {
			if c.Child != nil {
				walk(c.Child)
			}
		}
	}
	walk(rr.Tree.Root)
	return dirs
}

// skipOwners returns the documents a discovery skip belongs to: every root whose tree loads
// the skipped path's directory, which then misses the file, or else the root whose directory
// most deeply contains the path, or else the first document (ADR 0046).
func skipOwners(roots []string, loaded []map[string]bool, p string) []int {
	dir := path.Dir(p)
	var owners []int
	for i, dirs := range loaded {
		if dirs[dir] {
			owners = append(owners, i)
		}
	}
	if len(owners) > 0 {
		return owners
	}
	return []int{skipOwner(roots, p)}
}

// skipOwner returns the index of the root whose directory most deeply contains p, or 0 (the
// first document) when none does.
func skipOwner(roots []string, p string) int {
	owner, depth := 0, -1
	for i, dir := range roots {
		d := -1
		switch {
		case dir == ".":
			d = 0
		case p == dir || strings.HasPrefix(p, dir+"/"):
			d = strings.Count(dir, "/") + 1
		}
		if d > depth {
			owner, depth = i, d
		}
	}
	return owner
}

// unexpressedGaps reports what NormalizeRoot could not express, at the resource or output it
// concerns.
func unexpressedGaps(doc *model.InputDocument, un Unexpressed) []model.CoverageGap {
	where := map[string]model.SourceLocation{}
	for _, r := range doc.Resources {
		where[r.Address] = model.SourceLocation{File: r.Source.File, Range: r.Source.Range}
	}
	for _, o := range doc.Outputs {
		where[qualify(o.Module, "output."+o.Name)] = o.SourceRange
	}
	var out []model.CoverageGap
	for _, addr := range un.IncompleteResources {
		loc := where[addr]
		out = append(out, model.CoverageGap{
			Kind:   model.GapIncompleteAnalysis,
			Detail: fmt.Sprintf("values of %s cannot be expressed as paths (ADR 0045)", addr),
			File:   loc.File, Line: loc.Range.StartLine,
		})
	}
	for _, addr := range un.IncompleteReferences {
		loc := where[addr]
		out = append(out, model.CoverageGap{
			Kind:   model.GapIncompleteReferences,
			Detail: fmt.Sprintf("references of %s may be incomplete", addr),
			File:   loc.File, Line: loc.Range.StartLine,
		})
	}
	return out
}

// sortedGaps sorts gaps by file, line, kind and detail and removes duplicates.
func sortedGaps(gaps []model.CoverageGap) []model.CoverageGap {
	slices.SortFunc(gaps, func(a, b model.CoverageGap) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line),
			cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Detail, b.Detail))
	})
	gaps = slices.Compact(gaps)
	if gaps == nil {
		return []model.CoverageGap{}
	}
	return gaps
}
