package sarif_test

import (
	"bytes"
	stdjson "encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/report/sarif"
)

var update = flag.Bool("update", false, "rewrite the SARIF golden file")

const schemaID = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

func validate(t *testing.T, data []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "sarif-schema-2.1.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaID, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(schemaID)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(inst); err != nil {
		t.Errorf("SARIF does not validate against the 2.1.0 schema: %v", err)
	}
}

func finding(sev model.Severity, id, addr string) model.Finding {
	return model.Finding{
		RuleID: id, Title: "Rule " + id + " must hold", Severity: sev, CSP: "aws", Service: "s3", Status: model.StatusOpen,
		Message:    addr + " is not compliant",
		Resource:   model.FindingResource{Address: addr, Type: "aws_s3_bucket"},
		RootModule: ".", Location: model.Location{File: "infra/main.tf", StartLine: 3, StartColumn: 9, EndLine: 3, EndColumn: 22},
		Remediation:  "Set the attribute.",
		Frameworks:   map[string][]string{"aws-securityhub": {"S3.8"}},
		References:   []string{"https://docs.aws.amazon.com/s3/"},
		PolicySource: model.PolicySource{Name: "builtin", Version: "v1.2.3", Digest: "sha256:" + strings.Repeat("0", 64)},
		Fingerprint:  strings.Repeat("a", 64),
	}
}

func fixture() *model.Report {
	fs := []model.Finding{
		finding(model.SeverityCritical, "IACE-AWS-S3-002", "aws_s3_bucket.a"),
		finding(model.SeverityHigh, "IACE-AWS-EC2-001", "aws_instance.b"),
		finding(model.SeverityHigh, "IACE-AWS-EC2-001", "aws_instance.c"),
		finding(model.SeverityMedium, "IACE-AWS-S3-003", "aws_s3_bucket.d"),
		finding(model.SeverityLow, "IACE-AWS-S3-009", "aws_s3_bucket.e"),
		finding(model.SeverityInfo, "IACE-GEN-X-001", "aws_s3_bucket.f"),
	}
	fs[2].Status = model.StatusExcepted
	fs[2].Exception = &model.Exception{ID: "EXC-7", Owner: "platform", Reason: "legacy host", Expires: "2027-01-01", Ticket: "SEC-1"}
	fs[3].Location = model.Location{File: "infra/ünïcode.tf", StartLine: 4, StartColumn: 12, EndLine: 4, EndColumn: 20}
	fs[4].Resource = model.FindingResource{Address: "module.logs.aws_s3_bucket.e", Type: "aws_s3_bucket", Module: "module.logs"}
	fs[4].Message = "module.logs.aws_s3_bucket.e n'a pas de journal — ログなし"
	return &model.Report{
		Tool:           model.Tool{Name: "iace", Version: "v1.2.3", Commit: "abc"},
		Inputs:         []string{"infra"},
		Findings:       fs,
		CoverageGaps:   []model.ReportGap{{RootModule: "infra", CoverageGap: model.CoverageGap{Kind: model.GapUnresolvedModule, Detail: "remote module", File: "infra/main.tf", Line: 7}}},
		RulesEvaluated: 5, RulesLoaded: 6,
	}
}

func TestMarshalGolden(t *testing.T) {
	got, err := sarif.Marshal(fixture())
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "report.golden.sarif")
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
		t.Errorf("SARIF differs from %s (run go test -update and review the diff):\n%s", golden, got)
	}
	validate(t, got)
}

type parsed struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				SemanticVersion string `json:"semanticVersion"`
				Rules           []struct {
					ID                   string `json:"id"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
					Properties struct {
						SecuritySeverity *string  `json:"security-severity"`
						Tags             []string `json:"tags"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Invocations []struct {
			ToolExecutionNotifications []struct {
				Message struct{ Text string } `json:"message"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Level     string `json:"level"`
			Locations []struct {
				PhysicalLocation struct {
					Region map[string]any `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Suppressions []struct {
				Status        string `json:"status"`
				Justification string `json:"justification"`
			} `json:"suppressions"`
		} `json:"results"`
	} `json:"runs"`
}

func parse(t *testing.T, r *model.Report) parsed {
	t.Helper()
	data, err := sarif.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var p parsed
	if err := stdjson.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRuleIndexesPointAtTheirRules(t *testing.T) {
	run := parse(t, fixture()).Runs[0]
	if len(run.Tool.Driver.Rules) != 5 {
		t.Fatalf("%d rules, want one per rule with a finding (5)", len(run.Tool.Driver.Rules))
	}
	for _, res := range run.Results {
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) || run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("result for %s has ruleIndex %d", res.RuleID, res.RuleIndex)
		}
	}
}

func TestSeverityMapping(t *testing.T) {
	want := map[string][2]string{ // rule ID: level, security-severity ("" = absent)
		"IACE-AWS-S3-002": {"error", "9.5"}, "IACE-AWS-EC2-001": {"error", "8.0"},
		"IACE-AWS-S3-003": {"warning", "5.5"}, "IACE-AWS-S3-009": {"note", "3.0"}, "IACE-GEN-X-001": {"note", ""},
	}
	for _, r := range parse(t, fixture()).Runs[0].Tool.Driver.Rules {
		got := [2]string{r.DefaultConfiguration.Level, ""}
		if r.Properties.SecuritySeverity != nil {
			got[1] = *r.Properties.SecuritySeverity
		}
		if got != want[r.ID] {
			t.Errorf("%s: level and security-severity %v, want %v", r.ID, got, want[r.ID])
		}
		if r.Properties.Tags[0] != "security" {
			t.Errorf("%s: tags %v do not start with security", r.ID, r.Properties.Tags)
		}
	}
}

// Columns count grapheme clusters, which no SARIF column kind matches: regions carry lines only,
// also on a line with non-ASCII text before the finding (ADR 0052).
func TestRegionsAreLineLevel(t *testing.T) {
	for _, res := range parse(t, fixture()).Runs[0].Results {
		region := res.Locations[0].PhysicalLocation.Region
		if _, ok := region["startColumn"]; ok || region["endColumn"] != nil || region["startLine"] == nil {
			t.Errorf("%s: region %v, want lines only", res.RuleID, region)
		}
	}
}

func TestExceptedFindingsAreAcceptedSuppressions(t *testing.T) {
	results := parse(t, fixture()).Runs[0].Results
	got := 0
	for _, res := range results {
		for _, s := range res.Suppressions {
			got++
			if s.Status != "accepted" || !strings.Contains(s.Justification, "EXC-7") || !strings.Contains(s.Justification, "platform") {
				t.Errorf("suppression %+v", s)
			}
		}
	}
	if got != 1 {
		t.Errorf("%d suppressions, want 1", got)
	}
}

func TestGapsAndPartialRunsAreNotified(t *testing.T) {
	notes := parse(t, fixture()).Runs[0].Invocations[0].ToolExecutionNotifications
	var texts []string
	for _, n := range notes {
		texts = append(texts, n.Message.Text)
	}
	joined := strings.Join(texts, "\n")
	if !strings.Contains(joined, "coverage gap in infra: unresolved_module") || !strings.Contains(joined, "only 5 of 6 rules evaluated") {
		t.Errorf("notifications %q", texts)
	}
}

func TestTagsAreCapped(t *testing.T) {
	f := finding(model.SeverityHigh, "IACE-AWS-S3-001", "aws_s3_bucket.a")
	var ctrls []string
	for i := range 30 {
		ctrls = append(ctrls, fmt.Sprintf("C.%d", i))
	}
	f.Frameworks = map[string][]string{"aws-securityhub": ctrls}
	r := &model.Report{Tool: model.Tool{Version: "dev"}, Findings: []model.Finding{f}}
	run := parse(t, r).Runs[0]
	if n := len(run.Tool.Driver.Rules[0].Properties.Tags); n != 20 {
		t.Errorf("%d tags, want at most 20", n)
	}
	if run.Tool.Driver.SemanticVersion != "" {
		t.Errorf("semanticVersion %q for a non-semver build", run.Tool.Driver.SemanticVersion)
	}
}

func TestEmptyReportValidates(t *testing.T) {
	data, err := sarif.Marshal(&model.Report{Tool: model.Tool{Version: "dev"}, Inputs: []string{"."}})
	if err != nil {
		t.Fatal(err)
	}
	validate(t, data)
}

func TestURIsArePercentEncoded(t *testing.T) {
	f := finding(model.SeverityHigh, "IACE-AWS-S3-001", "aws_s3_bucket.a")
	f.Location.File = "infra/a#b c%.tf"
	data, err := sarif.Marshal(&model.Report{Tool: model.Tool{Version: "dev"}, Findings: []model.Finding{f}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"uri": "infra/a%23b%20c%25.tf"`) {
		t.Errorf("URI not percent-encoded:\n%s", data)
	}
	validate(t, data)
	f.Location.File = "a:b.tf"
	data, err = sarif.Marshal(&model.Report{Tool: model.Tool{Version: "dev"}, Findings: []model.Finding{f}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"uri": "a%3Ab.tf"`) {
		t.Errorf("a colon in the first segment would read as a scheme:\n%s", data)
	}
}

// The run leaves automationDetails out, so upload-sarif's category tells roots apart.
func TestNoAutomationDetails(t *testing.T) {
	data, err := sarif.Marshal(fixture())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "automationDetails") {
		t.Error("the run sets automationDetails, which would override the upload category")
	}
}

// With one scan path, file paths are relative to that path; the writer's Base names it, so URIs
// are relative to the directory iace ran in (ADR 0052).
func TestBasePrefixesURIs(t *testing.T) {
	f := finding(model.SeverityHigh, "IACE-AWS-S3-001", "aws_s3_bucket.a")
	f.Location.File = "modules/a#b.tf"
	r := &model.Report{Tool: model.Tool{Version: "dev"}, Findings: []model.Finding{f}}
	data, err := sarif.Writer{Base: "my infra/prod"}.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"uri": "my%20infra/prod/modules/a%23b.tf"`) {
		t.Errorf("URI not prefixed with the base:\n%s", data)
	}
	validate(t, data)
	if f.Location.File != "modules/a#b.tf" || r.Findings[0].Location.File != "modules/a#b.tf" {
		t.Error("the writer changed the report")
	}
	plain, err := sarif.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), `"uri": "modules/a%23b.tf"`) {
		t.Errorf("Marshal without a base changed the URI:\n%s", plain)
	}
}
