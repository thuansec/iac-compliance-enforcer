package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/policies"
)

// compile loads fsys as built-in rules and prepares the engine with the embedded capabilities.
func compile(t testing.TB, fsys fstest.MapFS, opts Options) (*Engine, error) {
	t.Helper()
	lib, err := Load(fsys, BuiltIn)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	caps, err := LoadCapabilities(policies.FS)
	if err != nil {
		t.Fatalf("LoadCapabilities: %v", err)
	}
	return New(context.Background(), lib, caps, opts)
}

func oneRule(body string) fstest.MapFS {
	return fstest.MapFS{"iace/rules/aws/s3/public_access/rule.rego": {Data: []byte(rule(s3pkg, nil, body))}}
}

func bucketDoc(n int) *model.InputDocument {
	doc := &model.InputDocument{SchemaVersion: model.InputSchemaVersion}
	for i := range n {
		addr := fmt.Sprintf("aws_s3_bucket.b%d", i)
		doc.Resources = append(doc.Resources, model.Resource{
			Address: addr, BaseAddress: addr, Mode: model.ModeManaged, Type: "aws_s3_bucket",
			Name: fmt.Sprintf("b%d", i), Values: model.Values{"bucket": fmt.Sprintf("b%d", i)},
		})
	}
	return doc
}

func TestEvaluateReturnsViolationsByRuleID(t *testing.T) {
	e, err := compile(t, oneRule(""), Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := e.Evaluate(context.Background(), bucketDoc(2))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got := res["IACE-AWS-S3-001"]; len(got) != 2 {
		t.Fatalf("violations %v, want 2 under the rule ID", res)
	}
	v, ok := res["IACE-AWS-S3-001"][0].(map[string]any)
	if !ok || v["address"] != "aws_s3_bucket.b0" {
		t.Errorf("first violation %v", res["IACE-AWS-S3-001"][0])
	}
}

func TestEvaluateRuleWithoutViolations(t *testing.T) {
	e, err := compile(t, oneRule(""), Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := e.Evaluate(context.Background(), bucketDoc(0))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v, ok := res["IACE-AWS-S3-001"]; !ok || len(v) != 0 {
		t.Errorf("result %v, want an empty set under the rule ID", res)
	}
}

// Capabilities are enforced when compiling in the engine, not only by opa check in CI.
func TestNewRejectsDeniedBuiltins(t *testing.T) {
	body := "deny contains v if {\n\tresp := http.send({\"method\": \"get\", \"url\": \"https://example.invalid\"})\n\tv := resp.body\n}\n"
	_, err := compile(t, oneRule(body), Options{})
	var pe *PolicyError
	if !errors.As(err, &pe) || pe.File != "iace/rules/aws/s3/public_access/rule.rego" || !strings.Contains(err.Error(), "http.send") {
		t.Errorf("error %v, want a compile error naming the file and http.send", err)
	}
}

func TestNewIsStrict(t *testing.T) {
	body := "deny contains v if {\n\tsome r in input.resources\n\tunused := 1\n\tv := r.address\n}\n"
	_, err := compile(t, oneRule(body), Options{})
	var pe *PolicyError
	if !errors.As(err, &pe) || !strings.Contains(err.Error(), "unused") {
		t.Errorf("error %v, want a strict-mode error for the unused variable", err)
	}
}

func TestEvaluateBuiltinErrorNamesTheRule(t *testing.T) {
	body := "deny contains v if {\n\tsome r in input.resources\n\tto_number(r.values.bucket) > 0\n\tv := r.address\n}\n"
	e, err := compile(t, oneRule(body), Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	doc := bucketDoc(1)
	doc.Resources[0].Values["bucket"] = "FAKE-secret-value-0000" // fake fixture value
	_, err = e.Evaluate(context.Background(), doc)
	var pe *PolicyError
	if !errors.As(err, &pe) || pe.RuleID != "IACE-AWS-S3-001" || pe.File != "iace/rules/aws/s3/public_access/rule.rego" {
		t.Fatalf("error %v, want a PolicyError naming the rule and its file", err)
	}
	if strings.Contains(err.Error(), "FAKE-secret-value-0000") {
		t.Errorf("error %q quotes the scanned value", err)
	}
	if !strings.Contains(err.Error(), "to_number") || !strings.Contains(err.Error(), "at line ") {
		t.Errorf("error %q does not name the builtin and its line", err)
	}
}

// A message prefix that is not a builtin name, such as a scanned value, is never quoted.
func TestEvalErrorQuotesOnlyBuiltinNames(t *testing.T) {
	e := &Engine{builtins: map[string]bool{"to_number": true}, ruleByFile: map[string]string{}}
	for msg, want := range map[string]string{
		"to_number: strconv.ParseFloat: parsing \"x\"": "eval_builtin_error in to_number at",
		"fakepassword: something":                      "eval_builtin_error at",
	} {
		err := e.evalError(&topdown.Error{Code: topdown.BuiltinErr, Message: msg, Location: &ast.Location{File: "f.rego", Row: 1, Col: 1}})
		if !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "fakepassword") {
			t.Errorf("message %q: error %q, want %q", msg, err, want)
		}
	}
}

// A builtin error in a helper module names the helper's file; the calling rule is not known.
func TestEvaluateBuiltinErrorInALibrary(t *testing.T) {
	fsys := oneRule("deny contains v if {\n\tsome r in input.resources\n\tx.num(r.values.bucket) > 0\n\tv := r.address\n}\n")
	fsys["iace/lib/x/x.rego"] = &fstest.MapFile{Data: []byte("package iace.lib.x\n\nnum(s) := to_number(s)\n")}
	src := strings.Replace(string(fsys["iace/rules/aws/s3/public_access/rule.rego"].Data), "\n\ndeny", "\n\nimport data.iace.lib.x\n\ndeny", 1)
	fsys["iace/rules/aws/s3/public_access/rule.rego"] = &fstest.MapFile{Data: []byte(src)}
	e, err := compile(t, fsys, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = e.Evaluate(context.Background(), bucketDoc(1))
	var pe *PolicyError
	if !errors.As(err, &pe) || pe.File != "iace/lib/x/x.rego" || pe.RuleID != "" {
		t.Errorf("error %v, want a PolicyError naming the library file", err)
	}
}

func TestNewRequiresCapabilities(t *testing.T) {
	lib, err := Load(oneRule(""), BuiltIn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), lib, nil, Options{}); err == nil {
		t.Error("New without capabilities succeeded: OPA's defaults allow network builtins")
	}
}

func TestEvaluateRejectsANilDocument(t *testing.T) {
	e, err := compile(t, oneRule(""), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Evaluate(context.Background(), nil); err == nil {
		t.Error("Evaluate(nil) succeeded")
	}
}

func TestEvaluateHonoursACancelledContext(t *testing.T) {
	e, err := compile(t, oneRule(""), Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Evaluate(ctx, bucketDoc(1)); !errors.Is(err, context.Canceled) {
		t.Errorf("error %v, want context.Canceled", err)
	}
}

func TestEvaluateTimesOut(t *testing.T) {
	// Every triple of resources: cubic, slow on 3,000 buckets.
	body := "deny contains v if {\n\tsome a in input.resources\n\tsome b in input.resources\n\tsome c in input.resources\n" +
		"\ta.name != b.name\n\tb.name != c.name\n\tv := a.address\n}\n"
	e, err := compile(t, oneRule(body), Options{Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	start := time.Now()
	_, err = e.Evaluate(context.Background(), bucketDoc(3000))
	var te *EvalTimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("error %v, want an *EvalTimeoutError", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("timeout took %v", d)
	}
}

func TestEvaluateAllKeepsOrderAndShares(t *testing.T) {
	e, err := compile(t, oneRule(""), Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	docs := make([]*model.InputDocument, 32)
	for i := range docs {
		docs[i] = bucketDoc(i % 5)
	}
	results, err := e.EvaluateAll(context.Background(), docs)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	for i, res := range results {
		if got := len(res["IACE-AWS-S3-001"]); got != i%5 {
			t.Errorf("document %d: %d violations, want %d", i, got, i%5)
		}
	}
}

// The prepared query is shared read-only: run Evaluate from many goroutines (meaningful under -race).
func TestEvaluateConcurrently(t *testing.T) {
	e, err := compile(t, oneRule(""), Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			res, err := e.Evaluate(context.Background(), bucketDoc(3))
			if err == nil && len(res["IACE-AWS-S3-001"]) != 3 {
				err = fmt.Errorf("result %v", res)
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestEvaluateAllStopsOnTheFirstError(t *testing.T) {
	body := "deny contains v if {\n\tsome r in input.resources\n\tto_number(r.values.bucket) > 0\n\tv := r.address\n}\n"
	e, err := compile(t, oneRule(body), Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	docs := []*model.InputDocument{bucketDoc(0), bucketDoc(1), bucketDoc(0)}
	_, err = e.EvaluateAll(context.Background(), docs)
	var pe *PolicyError
	if !errors.As(err, &pe) || pe.RuleID != "IACE-AWS-S3-001" {
		t.Errorf("error %v, want the failing document's PolicyError", err)
	}
}

func TestBuiltInPoliciesCompile(t *testing.T) {
	lib, err := Load(policies.FS, BuiltIn)
	if err != nil {
		t.Fatal(err)
	}
	caps, err := LoadCapabilities(policies.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), lib, caps, Options{}); err != nil {
		t.Errorf("New(built-in policies): %v", err)
	}
}

// BenchmarkEvaluate evaluates every built-in rule over synthetic documents of 1k and 5k
// resources (the budget is in iace-architecture: 1k under 2 s, 5k under 10 s for a whole scan).
func BenchmarkEvaluate(b *testing.B) {
	lib, err := Load(policies.FS, BuiltIn)
	if err != nil {
		b.Fatal(err)
	}
	caps, err := LoadCapabilities(policies.FS)
	if err != nil {
		b.Fatal(err)
	}
	e, err := New(context.Background(), lib, caps, Options{})
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range []int{1000, 5000} {
		doc := instanceDoc(n)
		b.Run(fmt.Sprintf("resources=%d", n), func(b *testing.B) {
			for b.Loop() {
				if _, err := e.Evaluate(context.Background(), doc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// instanceDoc builds n EC2 instances, half of them without IMDSv2.
func instanceDoc(n int) *model.InputDocument {
	doc := &model.InputDocument{SchemaVersion: model.InputSchemaVersion, ProviderVersions: map[string]string{}}
	for i := range n {
		addr := fmt.Sprintf("aws_instance.i%d", i)
		tokens := "optional"
		if i%2 == 0 {
			tokens = "required"
		}
		doc.Resources = append(doc.Resources, model.Resource{
			Address: addr, BaseAddress: addr, Mode: model.ModeManaged, Type: "aws_instance",
			Name: fmt.Sprintf("i%d", i), Provider: "registry.terraform.io/hashicorp/aws",
			Values: model.Values{"ami": "ami-00000000", "metadata_options": []any{map[string]any{"http_tokens": tokens}}},
		})
	}
	return doc
}
