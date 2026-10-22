package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/thuansec/iac-compliance-enforcer/internal/engine"
	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/redact"
	"github.com/thuansec/iac-compliance-enforcer/internal/version"
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
	// Policies holds the rules and capabilities.json; nil means the built-in library. Until
	// external bundles (M8) it is a test seam: the report names it "builtin" either way.
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
	digest, err := PolicyDigest(fsys)
	if err != nil {
		return nil, err
	}
	info := version.Get()
	r := &model.Report{
		Tool:          model.Tool{Name: info.Name, Version: info.Version, Commit: info.Commit},
		PolicySources: []model.PolicySource{{Name: "builtin", Version: info.Version, Digest: digest}},
		Findings:      []model.Finding{}, CoverageGaps: []model.ReportGap{}, Warnings: []string{},
		RulesEvaluated: e.Rules(), RulesLoaded: len(lib.Rules),
	}
	for i, doc := range docs {
		fs, err := e.Findings(doc, results[i])
		if err != nil {
			return nil, err
		}
		for j := range fs {
			fs[j].PolicySource = r.PolicySources[0]
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

// PolicyDigest is "sha256:" and the hex SHA-256 over every file of a policy library, in
// lexical path order, each as its path, a NUL, its length, a NUL and its content: the same
// library always has the same digest, and any change to a file, name or set of files changes it.
func PolicyDigest(fsys fs.FS) (string, error) {
	h := sha256.New()
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		// A hash.Hash's Write never returns an error.
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", name, len(data))
		_, _ = h.Write(data)
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("policy digest: %w", err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
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

// ScanPaths scans each of paths and merges the reports. With one path it is Scan. With several,
// every root module, file and fingerprint is qualified by its path ("infra/prod" + "." is
// "infra/prod"), so roots with the same name under different paths never collide; a repeated
// path is scanned once, and any path that fails fails the run.
func ScanPaths(ctx context.Context, paths []string, opts ScanOptions) (*model.Report, error) {
	var unique []string
	for _, p := range paths {
		if c := filepath.ToSlash(filepath.Clean(p)); !slices.Contains(unique, c) {
			unique = append(unique, c)
		}
	}
	if len(unique) == 1 {
		return Scan(ctx, paths[0], opts)
	}
	if err := checkPaths(unique); err != nil {
		return nil, err
	}
	// Sorted, so the order of the arguments never changes the report.
	slices.Sort(unique)
	merged := &model.Report{Findings: []model.Finding{}, CoverageGaps: []model.ReportGap{}, Warnings: []string{}}
	for i, p := range unique {
		r, err := Scan(ctx, p, opts)
		if err != nil {
			return nil, err
		}
		for _, f := range r.Findings {
			f.RootModule = qualify(p, f.RootModule)
			f.Location.File = qualify(p, f.Location.File)
			f.Fingerprint = model.Fingerprint(f.RuleID, f.RootModule, f.Resource.Address, f.AttributePath)
			merged.Findings = append(merged.Findings, f)
		}
		for _, g := range r.CoverageGaps {
			g.RootModule = qualify(p, g.RootModule)
			if g.File != "" {
				g.File = qualify(p, g.File)
			}
			merged.CoverageGaps = append(merged.CoverageGaps, g)
		}
		for _, in := range r.Inputs {
			merged.Inputs = append(merged.Inputs, qualify(p, in))
		}
		s := &merged.Summary
		s.Critical += r.Summary.Critical
		s.High += r.Summary.High
		s.Medium += r.Summary.Medium
		s.Low += r.Summary.Low
		s.Info += r.Summary.Info
		s.Blocking += r.Summary.Blocking
		s.FailOn = r.Summary.FailOn
		merged.Hidden += r.Hidden
		merged.Warnings = append(merged.Warnings, r.Warnings...)
		s.Open += r.Summary.Open
		s.Excepted += r.Summary.Excepted
		merged.MinSeverity = r.MinSeverity
		if i == 0 {
			merged.RulesEvaluated, merged.RulesLoaded = r.RulesEvaluated, r.RulesLoaded
			merged.Tool, merged.PolicySources = r.Tool, r.PolicySources
		}
	}
	slices.Sort(merged.Inputs)
	slices.Sort(merged.Warnings)
	merged.Warnings = slices.Compact(merged.Warnings)
	engine.SortFindings(merged.Findings)
	return merged, nil
}

// PathError is a set of scan paths that cannot be named unambiguously (ADR 0050). It names
// the path: paths are positional arguments, not secrets.
type PathError struct {
	Path string
	Why  string
}

func (e *PathError) Error() string { return e.Path + ": " + e.Why }

// checkPaths requires several scan paths to be relative to the working directory, inside it,
// and disjoint: a path inside another would scan, report and count its root modules twice.
func checkPaths(paths []string) error {
	for _, p := range paths {
		if filepath.IsAbs(p) || p == ".." || strings.HasPrefix(p, "../") {
			return &PathError{Path: p, Why: "with several paths, each must be inside the working directory (see RelativePaths)"}
		}
		for _, q := range paths {
			if p != q && (p == "." || strings.HasPrefix(q, p+"/")) {
				return &PathError{Path: q, Why: "is inside another scan path (" + p + "); scan disjoint paths"}
			}
		}
	}
	return nil
}

// RelativePaths rewrites paths relative to the working directory cwd when there are several of
// them, so the names in a report (root modules, files, fingerprints) never carry the runner's
// checkout directory (ADR 0050). A path outside cwd is a *PathError. A single path is returned
// as it is: it is the scan root, and nothing is qualified by it.
func RelativePaths(cwd string, paths []string) ([]string, error) {
	if len(paths) < 2 {
		return paths, nil
	}
	out := make([]string, len(paths))
	for i, p := range paths {
		abs := p
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(cwd, p)
		}
		rel, err := filepath.Rel(cwd, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, &PathError{Path: p, Why: "is outside the working directory; with several paths, run iace from a directory that contains them all"}
		}
		out[i] = rel
	}
	return out, nil
}

// SingleScanBase returns the scan path relative to cwd, slash-separated, when paths name one
// directory other than cwd itself (as ScanPaths deduplicates them), and "" otherwise: with
// several paths files are already named by their path, and a path outside cwd cannot be named
// relative to it. The SARIF writer prefixes its URIs with it (ADR 0052).
func SingleScanBase(cwd string, paths []string) string {
	var unique []string
	for _, p := range paths {
		if c := filepath.ToSlash(filepath.Clean(p)); !slices.Contains(unique, c) {
			unique = append(unique, c)
		}
	}
	if len(unique) != 1 {
		return ""
	}
	abs := filepath.FromSlash(unique[0])
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return filepath.ToSlash(rel)
}

// qualify names rel (a root module or file, relative to the scan path) by the scan path.
func qualify(path, rel string) string {
	return filepath.ToSlash(filepath.Join(path, rel))
}
