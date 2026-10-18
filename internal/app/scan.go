package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"

	"github.com/thuansec/iac-compliance-enforcer/internal/engine"
	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/redact"
	"github.com/thuansec/iac-compliance-enforcer/policies"
)

// ScanOptions are the trusted settings of a scan.
type ScanOptions struct {
	InspectOptions
	// FailOn is the lowest severity that blocks (a model.Severity or model.FailOnNone).
	FailOn string
	// MinSeverity hides findings below it from the report; they still count as blocking.
	// Empty shows everything.
	MinSeverity model.Severity
	// Rules, when not empty, evaluates only these rule IDs (*engine.UnknownRuleError otherwise).
	Rules []string
	// Policies holds the rules and capabilities.json; nil means the built-in library.
	Policies fs.FS
}

// ErrNoRootModules is a scan path without Terraform: a mistyped path must never look clean.
var ErrNoRootModules = errors.New("no Terraform root modules under this path")

// Scan loads the Terraform under path, evaluates every rule over each root module and returns
// the report. A policy that fails to load, compile or evaluate is an error (*engine.PolicyError),
// as is a path without root modules. Parse errors are coverage gaps in the report: the caller
// decides that they make the scan untrustworthy (ParseErrors).
func Scan(ctx context.Context, path string, opts ScanOptions) (*model.Report, error) {
	fsys := opts.Policies
	if fsys == nil {
		fsys = policies.FS
	}
	lib, err := engine.Load(fsys, engine.BuiltIn)
	if err != nil {
		return nil, err
	}
	caps, err := engine.LoadCapabilities(fsys)
	if err != nil {
		return nil, err
	}
	e, err := engine.New(ctx, lib, caps, engine.Options{Rules: opts.Rules})
	if err != nil {
		return nil, err
	}
	docs, err := load(ctx, path, opts.InspectOptions)
	if err != nil {
		return nil, fmt.Errorf("scan %w", err)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("scan %s: %w", path, ErrNoRootModules)
	}
	results, err := e.EvaluateAll(ctx, docs)
	if err != nil {
		return nil, err
	}
	r := &model.Report{
		Findings: []model.Finding{}, CoverageGaps: []model.ReportGap{},
		RulesEvaluated: e.Rules(), RulesLoaded: len(lib.Rules),
	}
	for i, doc := range docs {
		fs, err := e.Findings(doc, results[i])
		if err != nil {
			return nil, err
		}
		r.Findings = append(r.Findings, fs...)
		r.Inputs = append(r.Inputs, doc.Source.RootModule)
		// Gap details come from the redacted document: the report is output.
		for _, g := range redact.Document(doc).CoverageGaps {
			r.CoverageGaps = append(r.CoverageGaps, model.ReportGap{RootModule: doc.Source.RootModule, CoverageGap: g})
		}
	}
	slices.Sort(r.Inputs)
	engine.SortFindings(r.Findings)
	r.Summary = model.Summarize(r.Findings, opts.FailOn)
	r.MinSeverity = opts.MinSeverity
	if r.MinSeverity == "" {
		r.MinSeverity = model.SeverityInfo
	}
	shown := r.Findings[:0:0]
	for _, f := range r.Findings {
		if f.Severity.Rank() >= r.MinSeverity.Rank() {
			shown = append(shown, f)
		}
	}
	r.Hidden = len(r.Findings) - len(shown)
	r.Findings = shown
	return r, nil
}

// ReportParseErrors counts the parse_error gaps of r: Terraform would refuse those files, so
// the scan is not trustworthy and exits 2.
func ReportParseErrors(r *model.Report) int {
	n := 0
	for _, g := range r.CoverageGaps {
		if g.Kind == model.GapParseError {
			n++
		}
	}
	return n
}
