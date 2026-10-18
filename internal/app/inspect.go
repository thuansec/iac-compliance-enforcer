// Package app holds iace's use cases (inspect, and later scan and fix). Each wires the
// components together for one command; flags, environment and output streams stay in the cli
// package.
package app

import (
	"context"
	"fmt"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/redact"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// InspectOptions are the trusted settings of an inspection. They come from the pipeline (flags
// or environment), never from the scanned repository.
type InspectOptions struct {
	// Vars and VarFiles set root variables, as terraform.VarOptions.
	Vars, VarFiles []string
	// TrustModuleManifest resolves remote module calls through .terraform/modules/modules.json
	// (ADR 0013): only a pipeline that prepared .terraform itself may set it.
	TrustModuleManifest bool
}

// Inspect loads the Terraform under path without executing anything and returns one redacted
// input document per root module, with its coverage gaps. A problem in the scanned files is a
// gap, not an error; an error means the path could not be read or ctx was cancelled.
func Inspect(ctx context.Context, path string, opts InspectOptions) ([]*model.InputDocument, error) {
	docs, err := load(ctx, path, opts)
	if err != nil {
		return nil, fmt.Errorf("inspect %w", err)
	}
	for i, doc := range docs {
		docs[i] = redact.Document(doc)
	}
	return docs, nil
}

// load reads the Terraform under path into one input document per root module, unredacted:
// policies judge the real values, and only output is redacted.
func load(ctx context.Context, path string, opts InspectOptions) ([]*model.InputDocument, error) {
	root, err := fsutil.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer func() { _ = root.Close() }() // read-only: a close error loses nothing

	limits := terraform.DefaultLimits()
	d, err := terraform.Discover(ctx, root, limits)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	mods, err := terraform.ClassifyModules(ctx, root, d, limits)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	vars := terraform.VarOptions{Vars: opts.Vars, VarFiles: opts.VarFiles}
	results, err := terraform.EvaluateRoots(ctx, root, d, mods, vars, limits,
		terraform.TreeOptions{TrustModuleManifest: opts.TrustModuleManifest})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return terraform.Documents(d, results), nil
}

// ParseErrors counts the parse_error gaps of docs: the configuration could not be read as
// Terraform would read it, so the result is not trustworthy and commands exit 2.
func ParseErrors(docs []*model.InputDocument) int {
	n := 0
	for _, doc := range docs {
		for _, g := range doc.CoverageGaps {
			if g.Kind == model.GapParseError {
				n++
			}
		}
	}
	return n
}
