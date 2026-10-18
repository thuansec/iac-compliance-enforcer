package text_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/report/text"
)

func finding(sev model.Severity, id, addr, msg string) model.Finding {
	return model.Finding{
		RuleID: id, Severity: sev, Status: model.StatusOpen, Message: msg, Remediation: "Fix it.",
		Resource: model.FindingResource{Address: addr}, Location: model.Location{File: "main.tf", StartLine: 3},
	}
}

func TestWriteGroupsBySeverity(t *testing.T) {
	fs := []model.Finding{
		finding(model.SeverityCritical, "IACE-AWS-S3-002", "aws_s3_bucket.a", "Public write."),
		finding(model.SeverityHigh, "IACE-AWS-EC2-001", "aws_instance.b", "IMDSv1.\nFORGED  line"),
	}
	r := &model.Report{
		Inputs:       []string{".", "child"},
		Findings:     fs,
		CoverageGaps: []model.ReportGap{{RootModule: ".", CoverageGap: model.CoverageGap{Kind: model.GapParseError, File: "x.tf", Line: 2, Detail: "bad"}}},
		Summary:      model.Summarize(fs, "high"),
	}
	var b bytes.Buffer
	if err := text.Write(&b, r); err != nil {
		t.Fatal(err)
	}
	want := `CRITICAL
  main.tf:3  IACE-AWS-S3-002  aws_s3_bucket.a  Public write.
    fix: Fix it.

HIGH
  main.tf:3  IACE-AWS-EC2-001  aws_instance.b  IMDSv1. FORGED line
    fix: Fix it.

Coverage gaps: 1
  .: parse_error x.tf:2 bad
2 findings (critical 1, high 1, medium 0, low 0, info 0); 2 blocking at fail-on high
Scanned 2 root modules: ., child
`
	if got := b.String(); got != want {
		t.Errorf("report:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteClean(t *testing.T) {
	var b bytes.Buffer
	r := &model.Report{Inputs: []string{"."}, Summary: model.Summarize(nil, "none")}
	if err := text.Write(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "No findings.\n") || !strings.Contains(b.String(), "0 findings (") {
		t.Errorf("report %q", b.String())
	}
}

// Names from the scanned repository cannot forge lines or send terminal escapes.
func TestWriteSanitizesRepositoryNames(t *testing.T) {
	f := finding(model.SeverityHigh, "IACE-AWS-EC2-001", "aws_instance.b", "m")
	f.Location.File = "evil\nHIGH\n  main.tf:1  FORGED\x1b[2J.tf"
	r := &model.Report{Inputs: []string{"dir\nx"}, Findings: []model.Finding{f}, Summary: model.Summarize([]model.Finding{f}, "high")}
	var b bytes.Buffer
	if err := text.Write(&b, r); err != nil {
		t.Fatal(err)
	}
	if strings.Count(b.String(), "HIGH") != 2 || strings.ContainsRune(b.String(), 0x1b) || strings.Contains(b.String(), "dir\nx") {
		t.Errorf("report:\n%s", b.String())
	}
}

// Some findings shown, some hidden: the shown group, the hidden count and the full total.
func TestWriteHidesBelowMinSeverity(t *testing.T) {
	all := []model.Finding{
		finding(model.SeverityHigh, "IACE-AWS-EC2-001", "aws_instance.a", "m"),
		finding(model.SeverityLow, "IACE-AWS-S3-009", "aws_s3_bucket.b", "m"),
	}
	r := &model.Report{
		Inputs: []string{"."}, Findings: all[:1], MinSeverity: model.SeverityMedium, Hidden: 1,
		Summary: model.Summarize(all, "high"), RulesEvaluated: 1, RulesLoaded: 3,
	}
	var b bytes.Buffer
	if err := text.Write(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"HIGH\n",
		"1 finding hidden below --min-severity medium\n",
		"2 findings (critical 0, high 1, medium 0, low 1, info 0); 1 blocking at fail-on high\n",
		"Only 1 of 3 rules evaluated (--rule): the others were not checked\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "LOW") {
		t.Errorf("hidden finding printed:\n%s", out)
	}
}
