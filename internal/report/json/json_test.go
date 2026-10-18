package json_test

import (
	"bytes"
	stdjson "encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	reportjson "github.com/thuansec/iac-compliance-enforcer/internal/report/json"
)

var update = flag.Bool("update", false, "rewrite the JSON report golden file")

func schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "schemas", "findings.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(reportjson.SchemaID, raw); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(reportjson.SchemaID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// fixture covers every severity, a finding with and without an attribute path, an index step,
// a module resource, several frameworks, unicode in a message, a hidden count, a partial rule
// selection, a coverage gap and a warning.
func fixture() *model.Report {
	f := func(sev model.Severity, id, addr string, path model.Path) model.Finding {
		return model.Finding{
			RuleID: id, Title: "Title of " + id, Severity: sev, CSP: "aws", Service: "s3", Status: model.StatusOpen,
			Message:    addr + " is not compliant — détail",
			Resource:   model.FindingResource{Address: addr, Type: "aws_s3_bucket", Module: "", Provider: "registry.terraform.io/hashicorp/aws"},
			RootModule: ".", Location: model.Location{File: "main.tf", StartLine: 3, StartColumn: 1, EndLine: 5, EndColumn: 2},
			AttributePath: path, Remediation: "Fix it.",
			Frameworks:   map[string][]string{"cis-aws@5.0.0": {"2.1.4"}, "aws-securityhub": {"S3.8", "S3.1"}},
			References:   []string{"https://docs.aws.amazon.com/s3/"},
			PolicySource: model.PolicySource{Name: "builtin", Version: "v0.0.0-test", Digest: "sha256:" + strings.Repeat("ab", 32)},
			Fingerprint:  model.Fingerprint(id, ".", addr, path),
		}
	}
	fs := []model.Finding{
		f(model.SeverityCritical, "IACE-AWS-S3-002", "aws_s3_bucket.a", model.Path{model.AttrStep("acl")}),
		f(model.SeverityHigh, "IACE-AWS-EC2-001", "aws_instance.b", model.Path{model.AttrStep("metadata_options"), model.IndexStep(0), model.AttrStep("http_tokens")}),
		f(model.SeverityMedium, "IACE-AWS-S3-005", "module.logs.aws_s3_bucket.c", nil),
	}
	fs[2].Resource.Module = "module.logs"
	fs[1].Status = model.StatusExcepted
	fs[1].Exception = &model.Exception{ID: "EXC-1", Owner: "platform", Reason: "legacy host", Expires: "2027-01-01", Ticket: "SEC-12"}
	fs[2].Frameworks = map[string][]string{}
	return &model.Report{
		Tool:           model.Tool{Name: "iace", Version: "v0.0.0-test", Commit: "0000000"},
		PolicySources:  []model.PolicySource{{Name: "builtin", Version: "v0.0.0-test", Digest: "sha256:" + strings.Repeat("ab", 32)}},
		Inputs:         []string{"."},
		Findings:       fs,
		MinSeverity:    model.SeverityMedium,
		Hidden:         2,
		CoverageGaps:   []model.ReportGap{{RootModule: ".", CoverageGap: model.CoverageGap{Kind: model.GapParseError, Detail: "bad", File: "x.tf", Line: 2}}},
		Warnings:       []string{"rule IACE-AWS-S3-005 is deprecated"},
		RulesEvaluated: 3, RulesLoaded: 4,
		// The two hidden findings (one low, one info) count in the summary too.
		Summary: model.Summarize(append(slices.Clone(fs),
			model.Finding{Severity: model.SeverityLow, Status: model.StatusOpen},
			model.Finding{Severity: model.SeverityInfo, Status: model.StatusOpen}), "high"),
	}
}

func TestMarshalGolden(t *testing.T) {
	got, err := reportjson.Marshal(fixture())
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "report.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("report differs from %s (run go test -update and review the diff):\n%s", golden, got)
	}
}

func TestMarshalValidatesAgainstTheSchema(t *testing.T) {
	data, err := reportjson.Marshal(fixture())
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema(t).Validate(inst); err != nil {
		t.Errorf("report does not validate: %v", err)
	}
}

func TestMarshalEncodesPathsAndMapsDeterministically(t *testing.T) {
	a, err := reportjson.Marshal(fixture())
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		b, err := reportjson.Marshal(fixture())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatal("two encodings of the same report differ")
		}
	}
	var doc struct {
		Findings []struct {
			AttributePath stdjson.RawMessage `json:"attribute_path"`
		} `json:"findings"`
	}
	if err := stdjson.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc.Findings[2].AttributePath) != "null" {
		t.Errorf("attribute_path without a path = %s, want null", doc.Findings[2].AttributePath)
	}
	var compact bytes.Buffer
	if err := stdjson.Compact(&compact, doc.Findings[1].AttributePath); err != nil {
		t.Fatal(err)
	}
	if compact.String() != `["metadata_options",0,"http_tokens"]` {
		t.Errorf("attribute_path = %s", compact.String())
	}
	if strings.Index(string(a), `"aws-securityhub"`) > strings.Index(string(a), `"cis-aws@5.0.0"`) {
		t.Error("framework keys are not sorted")
	}
}

func TestEmptyReportHasNoNulls(t *testing.T) {
	r := &model.Report{
		Tool:          model.Tool{Name: "iace", Version: "dev", Commit: "dev"},
		PolicySources: []model.PolicySource{{Name: "builtin", Version: "dev", Digest: "sha256:" + strings.Repeat("0", 64)}},
		Inputs:        []string{"."}, MinSeverity: model.SeverityInfo,
		Summary: model.Summary{FailOn: "high"},
	}
	data, err := reportjson.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema(t).Validate(inst); err != nil {
		t.Errorf("an empty report does not validate: %v\n%s", err, data)
	}
}

// Every JSON field of model.Finding reaches the report: a field added to the model and not to
// the report document fails here instead of silently missing from the JSON.
func TestFindingFieldsAreAllReported(t *testing.T) {
	model := jsonTags(reflect.TypeFor[model.Finding]())
	report := jsonTags(reflect.TypeFor[reportjson.FindingForTest]())
	for name := range model {
		if !report[name] {
			t.Errorf("model.Finding field %q is not in the JSON report", name)
		}
	}
	// Fields the report adds beyond the model, documented in the schema.
	for name := range report {
		if !model[name] && name != "ai_suggestion" {
			t.Errorf("the JSON report has %q, which model.Finding lacks", name)
		}
	}
}

func jsonTags(t reflect.Type) map[string]bool {
	tags := map[string]bool{}
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		tags[name] = true
	}
	return tags
}
