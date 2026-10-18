package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	reportjson "github.com/thuansec/iac-compliance-enforcer/internal/report/json"
)

// A real scan's JSON report validates against schemas/findings.v1.json.
func TestScanJSONValidatesAgainstTheSchema(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", "findings.v1.json")) // before t.Chdir
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
	schema, err := c.Compile(reportjson.SchemaID)
	if err != nil {
		t.Fatal(err)
	}
	// Several paths must lie inside the working directory: scan from the repository root.
	t.Chdir(filepath.Join("..", ".."))
	fixture := func(dir string) string { return filepath.Join("testdata", "policies", dir) }
	for _, paths := range [][]string{
		{fixture("IACE-AWS-VPC-001/fail")},
		{fixture("IACE-AWS-EC2-001/pass")},
		{fixture("IACE-AWS-VPC-001/fail"), fixture("IACE-AWS-S3-001/fail")},
	} {
		dir := strings.Join(paths, " ")
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), append([]string{"scan", "-o", "json"}, paths...), &stdout, &stderr)
		if code == exitError {
			t.Fatalf("%s: exit %d: %s", dir, code, stderr.String())
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(stdout.Bytes()))
		if err != nil {
			t.Fatalf("%s: %v\n%s", dir, err, stdout.String())
		}
		if err := schema.Validate(inst); err != nil {
			t.Errorf("%s: report does not validate: %v", dir, err)
		}
	}
}

// A real scan's SARIF validates against the vendored SARIF 2.1.0 schema.
func TestScanSARIFValidatesAgainstTheSchema(t *testing.T) {
	const id = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	data, err := os.ReadFile(filepath.Join("..", "report", "sarif", "testdata", "sarif-schema-2.1.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(id, raw); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile(id)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "-o", "sarif", filepath.Join("..", "..", "testdata", "policies", "IACE-AWS-VPC-001", "fail")}, &stdout, &stderr)
	if code != exitBlocking {
		t.Fatalf("exit %d, want 1: %s", code, stderr.String())
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(inst); err != nil {
		t.Errorf("SARIF does not validate: %v", err)
	}
}
