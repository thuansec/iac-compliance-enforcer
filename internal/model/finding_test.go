package model_test

import (
	"regexp"
	"testing"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

func TestFingerprintIsStable(t *testing.T) {
	path := model.Path{model.AttrStep("metadata_options"), model.IndexStep(0), model.AttrStep("http_tokens")}
	a := model.Fingerprint("IACE-AWS-EC2-001", "infra", "aws_instance.web", path)
	if a != model.Fingerprint("IACE-AWS-EC2-001", "infra", "aws_instance.web", path) {
		t.Fatal("same inputs, different fingerprints")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a) {
		t.Errorf("fingerprint %q is not a hex sha256", a)
	}
	// Pinned (sha256 of ["IACE-AWS-EC2-001","infra","aws_instance.web",["metadata_options",0,"http_tokens"]]):
	// a change of the encoding changes every stored baseline and exception.
	if want := "263ea87a6aed76a107d2f10ac76c5aa91ab83fe07ab854b2b61b4dc527e49deb"; a != want {
		t.Errorf("fingerprint %s, want %s", a, want)
	}
}

// Each component is delimited: moving characters between fields, or an index step that spells
// like a name, gives another fingerprint.
func TestFingerprintSeparatesItsParts(t *testing.T) {
	base := model.Fingerprint("IACE-AWS-S3-001", "infra", "aws_s3_bucket.b", nil)
	for name, got := range map[string]string{
		"field boundary":  model.Fingerprint("IACE-AWS-S3-001i", "nfra", "aws_s3_bucket.b", nil),
		"root vs address": model.Fingerprint("IACE-AWS-S3-001", "infraa", "ws_s3_bucket.b", nil),
		"empty path":      model.Fingerprint("IACE-AWS-S3-001", "infra", "aws_s3_bucket.b", model.Path{}),
		"other rule":      model.Fingerprint("IACE-AWS-S3-002", "infra", "aws_s3_bucket.b", nil),
		"index vs name 0": model.Fingerprint("IACE-AWS-S3-001", "infra", "aws_s3_bucket.b", model.Path{model.IndexStep(0)}),
		"name 0 vs index": model.Fingerprint("IACE-AWS-S3-001", "infra", "aws_s3_bucket.b", model.Path{model.AttrStep("0")}),
	} {
		if got == base {
			t.Errorf("%s: same fingerprint as the base", name)
		}
	}
	if model.Fingerprint("r", "m", "a", model.Path{model.IndexStep(0)}) == model.Fingerprint("r", "m", "a", model.Path{model.AttrStep("0")}) {
		t.Error("an index step and a name step that spell alike share a fingerprint")
	}
}

func TestSeverityRank(t *testing.T) {
	order := []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo}
	for i := 1; i < len(order); i++ {
		if order[i-1].Rank() <= order[i].Rank() {
			t.Errorf("%s ranks no higher than %s", order[i-1], order[i])
		}
	}
}

func TestSummarize(t *testing.T) {
	f := func(s model.Severity, st model.Status) model.Finding { return model.Finding{Severity: s, Status: st} }
	fs := []model.Finding{
		f(model.SeverityCritical, model.StatusOpen), f(model.SeverityHigh, model.StatusOpen),
		f(model.SeverityHigh, model.StatusExcepted), f(model.SeverityMedium, model.StatusOpen),
		f(model.SeverityLow, model.StatusOpen), f(model.SeverityInfo, model.StatusOpen),
	}
	for failOn, blocking := range map[string]int{"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5, model.FailOnNone: 0} {
		s := model.Summarize(fs, failOn)
		if s.Blocking != blocking || s.Critical != 1 || s.High != 2 || s.Medium != 1 || s.Low != 1 || s.Info != 1 || s.FailOn != failOn {
			t.Errorf("fail-on %s: %+v, want %d blocking (excepted findings never block)", failOn, s, blocking)
		}
	}
}
