package app

import (
	"context"
	"io/fs"
	"slices"
	"strings"

	"github.com/thuansec/iac-compliance-enforcer/internal/engine"
	"github.com/thuansec/iac-compliance-enforcer/policies"
)

// Rules loads the policy library (nil means the built-in one), checks it exactly as a scan does
// (metadata, then compilation against the capabilities) and returns its rules sorted by ID. A
// library a scan would refuse is an error here too, so a rule is never listed as loaded when
// it cannot run.
func Rules(ctx context.Context, fsys fs.FS) ([]engine.Rule, error) {
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
	if _, err := engine.New(ctx, lib, caps, engine.Options{}); err != nil {
		return nil, err
	}
	rules := slices.Clone(lib.Rules)
	slices.SortFunc(rules, func(a, b engine.Rule) int { return strings.Compare(a.ID, b.ID) })
	return rules, nil
}
