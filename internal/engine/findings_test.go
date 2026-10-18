package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// jsonNumber is how OPA's results carry numbers.
func jsonNumber(s string) json.Number { return json.Number(s) }

func findingsDoc() *model.InputDocument {
	return &model.InputDocument{
		SchemaVersion: model.InputSchemaVersion,
		Source:        model.DocumentSource{Kind: model.SourceHCL, RootModule: "infra"},
		Resources: []model.Resource{{
			Address: "aws_s3_bucket.b", BaseAddress: "aws_s3_bucket.b", Mode: model.ModeManaged,
			Type: "aws_s3_bucket", Name: "b", Module: "", Provider: "registry.terraform.io/hashicorp/aws",
			Values: model.Values{"acl": "public-read"},
			Source: model.ResourceSource{
				File:  "main.tf",
				Range: model.Range{StartLine: 10, StartColumn: 1, EndLine: 14, EndColumn: 2},
				Attributes: map[string]model.Range{
					"acl":                  {StartLine: 3, StartColumn: 9, EndLine: 3, EndColumn: 22},
					"versioning.0.enabled": {StartLine: 12, StartColumn: 15, EndLine: 12, EndColumn: 20},
				},
				AttributeFiles: map[string]string{"acl": "main_override.tf"},
			},
		}},
	}
}

func decodeEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := compile(t, oneRule(""), Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestFindingsFromViolations(t *testing.T) {
	e := decodeEngine(t)
	doc := findingsDoc()
	res := Result{"IACE-AWS-S3-001": {
		map[string]any{"address": "aws_s3_bucket.b", "message": "Bucket is public.", "attribute_path": []any{"acl"}},
		map[string]any{"address": "aws_s3_bucket.b", "message": "Versioning is off.", "attribute_path": []any{"versioning", jsonNumber("0"), "enabled"}},
		map[string]any{"address": "aws_s3_bucket.b", "message": "No logging.", "x_extra": true},
	}}
	fs, err := e.Findings(doc, res)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(fs) != 3 {
		t.Fatalf("%d findings, want 3", len(fs))
	}
	byMsg := map[string]model.Finding{}
	for _, f := range fs {
		byMsg[f.Message] = f
	}
	acl := byMsg["Bucket is public."]
	if acl.Location != (model.Location{File: "main_override.tf", StartLine: 3, StartColumn: 9, EndLine: 3, EndColumn: 22}) {
		t.Errorf("acl location %+v, want the override file's attribute range (ADR 0048)", acl.Location)
	}
	if acl.RuleID != "IACE-AWS-S3-001" || acl.Severity != model.SeverityHigh || acl.CSP != "aws" || acl.Service != "s3" ||
		acl.Title == "" || acl.Remediation == "" || len(acl.References) != 1 || acl.Status != model.StatusOpen ||
		acl.RootModule != "infra" || acl.Resource != (model.FindingResource{Address: "aws_s3_bucket.b", Type: "aws_s3_bucket", Provider: "registry.terraform.io/hashicorp/aws"}) {
		t.Errorf("finding %+v", acl)
	}
	if acl.Fingerprint != model.Fingerprint("IACE-AWS-S3-001", "infra", "aws_s3_bucket.b", model.Path{model.AttrStep("acl")}) {
		t.Errorf("fingerprint %s", acl.Fingerprint)
	}
	ver := byMsg["Versioning is off."]
	if ver.Location != (model.Location{File: "main.tf", StartLine: 12, StartColumn: 15, EndLine: 12, EndColumn: 20}) {
		t.Errorf("versioning location %+v, want the base file's attribute range", ver.Location)
	}
	if got := ver.AttributePath.String(); got != "versioning.0.enabled" || !ver.AttributePath[1].IsIndex() {
		t.Errorf("attribute path %v", ver.AttributePath)
	}
	block := byMsg["No logging."]
	if block.Location != (model.Location{File: "main.tf", StartLine: 10, StartColumn: 1, EndLine: 14, EndColumn: 2}) || block.AttributePath != nil {
		t.Errorf("no-path finding %+v, want the block range", block)
	}
}

// A path below a located attribute (into a map or a list value) uses the nearest located
// ancestor; a path nothing locates uses the block.
func TestFindingsLocateTheNearestAttribute(t *testing.T) {
	e := decodeEngine(t)
	res := Result{"IACE-AWS-S3-001": {
		map[string]any{"address": "aws_s3_bucket.b", "message": "a", "attribute_path": []any{"acl", "x"}},
		map[string]any{"address": "aws_s3_bucket.b", "message": "b", "attribute_path": []any{"logging", jsonNumber("0")}},
	}}
	fs, err := e.Findings(findingsDoc(), res)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		switch f.Message {
		case "a":
			if f.Location.File != "main_override.tf" || f.Location.StartLine != 3 {
				t.Errorf("acl.x location %+v, want acl's", f.Location)
			}
		case "b":
			if f.Location.StartLine != 10 {
				t.Errorf("logging.0 location %+v, want the block", f.Location)
			}
		}
	}
}

func TestFindingsAreSorted(t *testing.T) {
	src := rule("iace.rules.aws.s3.other", map[string]string{"id": "#   id: IACE-AWS-S3-002", "severity": "#   severity: critical"}, "")
	fsys := oneRule("")
	fsys["iace/rules/aws/s3/other/rule.rego"] = &fstest.MapFile{Data: []byte(src)}
	e, err := compile(t, fsys, Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := findingsDoc()
	other := doc.Resources[0]
	other.Address, other.BaseAddress, other.Name = "aws_s3_bucket.a", "aws_s3_bucket.a", "a"
	doc.Resources = append(doc.Resources, other)
	res := Result{
		"IACE-AWS-S3-001": {
			map[string]any{"address": "aws_s3_bucket.b", "message": "m"},
			map[string]any{"address": "aws_s3_bucket.a", "message": "m"},
		},
		"IACE-AWS-S3-002": {map[string]any{"address": "aws_s3_bucket.b", "message": "m"}},
	}
	fs, err := e.Findings(doc, res)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs {
		got = append(got, f.RuleID+" "+f.Resource.Address)
	}
	want := "IACE-AWS-S3-002 aws_s3_bucket.b|IACE-AWS-S3-001 aws_s3_bucket.a|IACE-AWS-S3-001 aws_s3_bucket.b"
	if strings.Join(got, "|") != want {
		t.Errorf("order %v, want %s (severity desc, rule, file, line, address)", got, want)
	}
}

// Every malformed violation is a PolicyError naming the rule; none quotes the violation's values.
func TestFindingsRejectMalformedViolations(t *testing.T) {
	e := decodeEngine(t)
	long := strings.Repeat("x", 501)
	for name, v := range map[string]any{
		"not an object":         "FAKE-secret-0000",
		"no address":            map[string]any{"message": "m"},
		"address not a string":  map[string]any{"address": 1, "message": "m"},
		"unknown address":       map[string]any{"address": "aws_s3_bucket.FAKE-secret-0000", "message": "m"},
		"no message":            map[string]any{"address": "aws_s3_bucket.b"},
		"empty message":         map[string]any{"address": "aws_s3_bucket.b", "message": " "},
		"message too long":      map[string]any{"address": "aws_s3_bucket.b", "message": long},
		"message not a string":  map[string]any{"address": "aws_s3_bucket.b", "message": []any{"FAKE-secret-0000"}},
		"path not a list":       map[string]any{"address": "aws_s3_bucket.b", "message": "m", "attribute_path": "acl"},
		"path element bool":     map[string]any{"address": "aws_s3_bucket.b", "message": "m", "attribute_path": []any{true}},
		"path negative index":   map[string]any{"address": "aws_s3_bucket.b", "message": "m", "attribute_path": []any{jsonNumber("-1")}},
		"path fractional index": map[string]any{"address": "aws_s3_bucket.b", "message": "m", "attribute_path": []any{jsonNumber("0.5")}},
		"path empty name":       map[string]any{"address": "aws_s3_bucket.b", "message": "m", "attribute_path": []any{""}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.Findings(findingsDoc(), Result{"IACE-AWS-S3-001": {v}})
			var pe *PolicyError
			if !errors.As(err, &pe) || pe.RuleID != "IACE-AWS-S3-001" || pe.File != "iace/rules/aws/s3/public_access/rule.rego" {
				t.Fatalf("error %v, want a PolicyError naming the rule", err)
			}
			if strings.Contains(err.Error(), "FAKE-secret-0000") || strings.Contains(err.Error(), long) {
				t.Errorf("error %q quotes the violation", err)
			}
		})
	}
}

func TestFindingsRejectUnknownRuleIDs(t *testing.T) {
	e := decodeEngine(t)
	if _, err := e.Findings(findingsDoc(), Result{"IACE-AWS-S3-999": {}}); err == nil {
		t.Error("a result for a rule the engine did not load was accepted")
	}
}

// End to end: the engine's own result decodes, so a built rule's violations become findings.
func TestEvaluateThenDecode(t *testing.T) {
	e := decodeEngine(t)
	doc := findingsDoc()
	res, err := e.Evaluate(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := e.Findings(doc, res)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(fs) != 1 || fs[0].Resource.Address != "aws_s3_bucket.b" || fs[0].Message != "x" {
		t.Errorf("findings %+v", fs)
	}
}

// OPA returns a policy's integer path steps as numbers the decoder accepts as indexes.
func TestEvaluateThenDecodeAnIndexedPath(t *testing.T) {
	body := "deny contains v if {\n\tsome r in input.resources\n\tv := {\"address\": r.address, \"message\": \"m\", \"attribute_path\": [\"versioning\", 0, \"enabled\"]}\n}\n"
	e, err := compile(t, oneRule(body), Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := findingsDoc()
	res, err := e.Evaluate(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := e.Findings(doc, res)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(fs) != 1 || !fs[0].AttributePath[1].IsIndex() || fs[0].Location.StartLine != 12 {
		t.Errorf("findings %+v, want versioning.0.enabled located at line 12", fs)
	}
}

// An empty path, a null one and none at all are the same finding with the same fingerprint.
func TestFindingsTreatAnEmptyPathAsNone(t *testing.T) {
	e := decodeEngine(t)
	var fps []string
	for _, v := range []map[string]any{
		{"address": "aws_s3_bucket.b", "message": "m"},
		{"address": "aws_s3_bucket.b", "message": "m", "attribute_path": nil},
		{"address": "aws_s3_bucket.b", "message": "m", "attribute_path": []any{}},
	} {
		fs, err := e.Findings(findingsDoc(), Result{"IACE-AWS-S3-001": {v}})
		if err != nil {
			t.Fatal(err)
		}
		if fs[0].AttributePath != nil || fs[0].Location.StartLine != 10 {
			t.Errorf("finding %+v, want no path and the block range", fs[0])
		}
		fps = append(fps, fs[0].Fingerprint)
	}
	if fps[0] != fps[1] || fps[1] != fps[2] {
		t.Errorf("fingerprints %v, want one", fps)
	}
}

func TestFindingsAcceptAMessageAtTheLimit(t *testing.T) {
	e := decodeEngine(t)
	for name, msg := range map[string]string{
		"500 ASCII":      strings.Repeat("x", 500),
		"500 multi-byte": strings.Repeat("é", 500),
		"499 ASCII":      strings.Repeat("x", 499),
	} {
		v := map[string]any{"address": "aws_s3_bucket.b", "message": msg}
		if _, err := e.Findings(findingsDoc(), Result{"IACE-AWS-S3-001": {v}}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	v := map[string]any{"address": "aws_s3_bucket.b", "message": strings.Repeat("é", 501)}
	if _, err := e.Findings(findingsDoc(), Result{"IACE-AWS-S3-001": {v}}); err == nil {
		t.Error("501 multi-byte characters accepted")
	}
}

// Moving the resource (lines added above it) moves the location but keeps the fingerprint.
func TestFindingsFingerprintSurvivesLineShifts(t *testing.T) {
	e := decodeEngine(t)
	shift := func(r model.Range) model.Range {
		r.StartLine += 7
		r.EndLine += 7
		return r
	}
	moved := findingsDoc()
	src := &moved.Resources[0].Source
	src.Range = shift(src.Range)
	attrs := map[string]model.Range{}
	for k, r := range src.Attributes {
		attrs[k] = shift(r)
	}
	src.Attributes = attrs
	v := map[string]any{"address": "aws_s3_bucket.b", "message": "m", "attribute_path": []any{"acl"}}
	before, err := e.Findings(findingsDoc(), Result{"IACE-AWS-S3-001": {v}})
	if err != nil {
		t.Fatal(err)
	}
	after, err := e.Findings(moved, Result{"IACE-AWS-S3-001": {v}})
	if err != nil {
		t.Fatal(err)
	}
	if before[0].Fingerprint != after[0].Fingerprint || after[0].Location.StartLine != before[0].Location.StartLine+7 {
		t.Errorf("before %+v, after %+v: want the same fingerprint at a shifted line", before[0], after[0])
	}
}
