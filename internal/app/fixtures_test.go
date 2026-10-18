package app

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/thuansec/iac-compliance-enforcer/internal/engine"
	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/policies"
)

// fixtureRoot holds one directory per rule ID (iace-testing, policy fixture harness).
const fixtureRoot = "../../testdata/policies"

// fixtureKinds are the directories every rule must have: violating HCL, violating .tf.json with
// nested blocks written as single objects (ADR 0006), compliant variants, and an unknown nested
// value, which is neither a violation nor a pass. Each may hold several root modules in
// subdirectories, scanned separately.
var fixtureKinds = []string{"fail", "fail_json", "pass", "unknown"}

type expectedFindings struct {
	Findings []struct {
		Address       string `yaml:"address"`
		AttributePath []any  `yaml:"attribute_path"`
	} `yaml:"findings"`
}

func builtInEngine(t *testing.T) (*engine.Engine, *engine.Library) {
	t.Helper()
	lib, err := engine.Load(policies.FS, engine.BuiltIn)
	if err != nil {
		t.Fatal(err)
	}
	caps, err := engine.LoadCapabilities(policies.FS)
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.New(context.Background(), lib, caps, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return e, lib
}

// TestFixtureHarnessIsComplete fails when a rule lacks a fixture directory, a directory names no
// rule, or a rule directory holds anything but the fixture kinds: a new rule cannot ship without
// fixtures, and a misnamed fixture cannot go unrun.
func TestFixtureHarnessIsComplete(t *testing.T) {
	_, lib := builtInEngine(t)
	ids := map[string]bool{}
	for _, r := range lib.Rules {
		ids[r.ID] = true
		for _, kind := range fixtureKinds {
			if fi, err := os.Stat(filepath.Join(fixtureRoot, r.ID, kind)); err != nil || !fi.IsDir() {
				t.Errorf("rule %s has no %s fixture (%s/%s/%s/)", r.ID, kind, fixtureRoot, r.ID, kind)
			}
		}
	}
	entries, err := os.ReadDir(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !ids[e.Name()] {
			t.Errorf("%s/%s names no loaded rule", fixtureRoot, e.Name())
			continue
		}
		kinds, err := os.ReadDir(filepath.Join(fixtureRoot, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range kinds {
			if !slices.Contains(fixtureKinds, k.Name()) {
				t.Errorf("%s/%s/%s is not one of %v: it would never run", fixtureRoot, e.Name(), k.Name(), fixtureKinds)
			}
		}
	}
}

func TestPolicyFixtures(t *testing.T) {
	e, lib := builtInEngine(t)
	for _, r := range lib.Rules {
		for _, kind := range fixtureKinds {
			dir := filepath.Join(fixtureRoot, r.ID, kind)
			if _, err := os.Stat(dir); err != nil {
				continue // reported by TestFixtureHarnessIsComplete
			}
			t.Run(r.ID+"/"+kind, func(t *testing.T) {
				docs, findings := scanFixture(t, e, dir)
				var got []string
				for _, f := range findings {
					if f.RuleID == r.ID {
						got = append(got, f.Resource.Address+" "+f.AttributePath.String())
					}
				}
				slices.Sort(got)
				switch kind {
				case "pass", "unknown":
					if len(got) > 0 {
						t.Errorf("findings %v, want none", got)
					}
				default:
					want, exp := expected(t, dir)
					if !slices.Equal(got, want) {
						t.Errorf("findings %v, want %v (expected.yaml)", got, want)
					}
					if kind == "fail_json" {
						checkSingleObjectBlocks(t, dir, docs, r, exp)
					}
				}
				if kind == "unknown" {
					checkUnknownNested(t, docs, r)
				}
			})
		}
	}
}

// scanFixture loads every root module under dir, unredacted as a scan does, and evaluates them.
func scanFixture(t *testing.T, e *engine.Engine, dir string) ([]*model.InputDocument, []model.Finding) {
	t.Helper()
	docs, err := load(context.Background(), dir, InspectOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n := ParseErrors(docs); n > 0 || len(docs) == 0 {
		t.Fatalf("%d documents, %d parse errors: fixtures must be valid Terraform", len(docs), n)
	}
	var all []model.Finding
	for _, doc := range docs {
		res, err := e.Evaluate(context.Background(), doc)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		fs, err := e.Findings(doc, res)
		if err != nil {
			t.Fatalf("findings: %v", err)
		}
		all = append(all, fs...)
	}
	return docs, all
}

// expected reads dir's expected.yaml strictly and returns its findings as sorted
// "address path" strings, with the parsed file.
func expected(t *testing.T, dir string) ([]string, expectedFindings) {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "expected.yaml"))
	if err != nil {
		t.Fatalf("a fail fixture needs expected.yaml: %v", err)
	}
	defer func() { _ = f.Close() }()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var exp expectedFindings
	if err := dec.Decode(&exp); err != nil {
		t.Fatalf("expected.yaml: %v", err)
	}
	if len(exp.Findings) == 0 {
		t.Fatal("expected.yaml lists no findings: a fail fixture must violate the rule")
	}
	var want []string
	for _, ef := range exp.Findings {
		parts := make([]string, len(ef.AttributePath))
		for i, p := range ef.AttributePath {
			switch p.(type) {
			case string, int:
				parts[i] = fmt.Sprint(p)
			default:
				t.Fatalf("expected.yaml: %s: path step %v is neither a name nor an index (quote names)", ef.Address, p)
			}
		}
		want = append(want, ef.Address+" "+strings.Join(parts, "."))
	}
	slices.Sort(want)
	return want, exp
}

// checkSingleObjectBlocks requires fail_json to hold .tf.json only, and every block its expected
// findings index into ([name, 0, ...]) to be written as one object (ADR 0006).
func checkSingleObjectBlocks(t *testing.T, dir string, docs []*model.InputDocument, r engine.Rule, ef expectedFindings) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".tf") {
			t.Errorf("fail_json holds %s: write it as .tf.json", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	blocks := map[string][]string{}
	for _, f := range ef.Findings {
		if len(f.AttributePath) >= 2 && f.AttributePath[1] == 0 {
			name, _ := f.AttributePath[0].(string)
			blocks[f.Address] = append(blocks[f.Address], name)
		}
	}
	if len(blocks) == 0 {
		t.Errorf("rule %s: fail_json's expected findings index into no nested block, so it cannot show the single-object shape", r.ID)
	}
	for _, doc := range docs {
		for _, res := range doc.Resources {
			for _, block := range blocks[res.Address] {
				if _, isObject := res.Values[block].(map[string]any); !isObject {
					t.Errorf("%s: %s is not written as a single object", res.Address, block)
				}
			}
		}
	}
}

// checkUnknownNested requires, in resources of the rule's types, an unknown value inside a
// nested block in both shapes (ADR 0006): from HCL, where the stored path holds the block's
// index, and from .tf.json with the block written as one object, where it has none. A rule that
// compares paths itself instead of calling tf.is_unknown fails one of them.
func checkUnknownNested(t *testing.T, docs []*model.InputDocument, r engine.Rule) {
	t.Helper()
	var fromHCL, fromJSON bool
	for _, doc := range docs {
		for _, res := range doc.Resources {
			if !slices.Contains(r.ResourceTypes, res.Type) {
				continue
			}
			isJSON := strings.HasSuffix(res.Source.File, ".tf.json")
			for _, p := range res.Unknown {
				if len(p) < 2 {
					continue
				}
				indexed := slices.ContainsFunc(p, model.PathStep.IsIndex)
				fromHCL = fromHCL || (!isJSON && indexed)
				fromJSON = fromJSON || (isJSON && !indexed)
			}
		}
	}
	if !fromHCL {
		t.Errorf("the unknown fixture has no unknown value inside an HCL nested block of a %v resource", r.ResourceTypes)
	}
	if !fromJSON {
		t.Errorf("the unknown fixture has no unknown value inside a .tf.json single-object block of a %v resource", r.ResourceTypes)
	}
}
