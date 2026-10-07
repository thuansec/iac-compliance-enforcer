package model_test

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

const schemaFile = "../../schemas/input.v1.json"

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// compileSchema compiles schemas/input.v1.json. The compiler only sees resources added here, so
// it never loads anything from the network.
func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := jsonschema.UnmarshalJSON(bytes.NewReader(readFile(t, schemaFile)))
	if err != nil {
		t.Fatalf("parse %s: %v", schemaFile, err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(model.InputSchemaID, raw); err != nil {
		t.Fatalf("add %s: %v", schemaFile, err)
	}
	s, err := c.Compile(model.InputSchemaID)
	if err != nil {
		t.Fatalf("compile %s: %v", schemaFile, err)
	}
	return s
}

func validate(t *testing.T, s *jsonschema.Schema, data []byte) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse instance: %v", err)
	}
	return s.Validate(inst)
}

// semantic decodes JSON into generic values, so two documents compare by content, not layout.
func semantic(t *testing.T, data []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func TestReferenceExampleRoundTrips(t *testing.T) {
	t.Parallel()
	example := readFile(t, "testdata/input-example.json")

	doc, err := model.DecodeInput(example)
	if err != nil {
		t.Fatalf("DecodeInput: %v", err)
	}
	got, err := model.EncodeInput(doc)
	if err != nil {
		t.Fatalf("EncodeInput: %v", err)
	}
	if diff := cmp.Diff(semantic(t, example), semantic(t, got)); diff != "" {
		t.Errorf("round trip changed the reference example (-want +got):\n%s", diff)
	}
}

func TestSchemaAcceptsReferenceExample(t *testing.T) {
	t.Parallel()
	if err := validate(t, compileSchema(t), readFile(t, "testdata/input-example.json")); err != nil {
		t.Errorf("schema rejects the reference example: %v", err)
	}
}

func TestSchemaIDMatchesConstant(t *testing.T) {
	t.Parallel()
	var head struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(readFile(t, schemaFile), &head); err != nil {
		t.Fatalf("decode %s: %v", schemaFile, err)
	}
	if head.ID != model.InputSchemaID {
		t.Errorf("$id = %q, want %q", head.ID, model.InputSchemaID)
	}
}

// fullDocument sets every field of every type, so the schema test below proves that each field
// the Go types emit is declared in the schema (which forbids additional properties).
func fullDocument() *model.InputDocument {
	yes := true
	loc := model.SourceLocation{File: "modules/net/main.tf", Range: model.Range{StartLine: 3, StartColumn: 1, EndLine: 8, EndColumn: 2}}
	return &model.InputDocument{
		SchemaVersion: model.InputSchemaVersion,
		Source:        model.DocumentSource{Kind: model.SourcePlan, RootModule: "infra/prod", PlanFile: "infra/prod/plan.json"},
		Terraform: model.TerraformSettings{
			RequiredVersion: ">= 1.6",
			Backend: &model.Backend{
				Type:    "s3",
				Values:  map[string]any{"bucket": "tf-state", "key": nil},
				Unknown: []model.Path{{model.AttrStep("key")}},
			},
			RequiredProviders: map[string]model.ProviderRequirement{
				"aws": {Source: "registry.terraform.io/hashicorp/aws", Version: "~> 6.0"},
			},
		},
		ProviderVersions: map[string]string{"registry.terraform.io/hashicorp/aws": "6.12.0"},
		Providers: []model.ProviderConfig{{
			LocalName:   "aws",
			Alias:       "eu",
			Source:      "registry.terraform.io/hashicorp/aws",
			Values:      map[string]any{"region": "eu-west-1", "access_key": "fake-access-key"},
			Unknown:     []model.Path{},
			Sensitive:   []model.Path{{model.AttrStep("access_key")}},
			SourceRange: loc,
		}},
		Resources: []model.Resource{
			{
				Address:        `module.net.aws_security_group.web["a"]`,
				BaseAddress:    "module.net.aws_security_group.web",
				Mode:           model.ModeManaged,
				Type:           "aws_security_group",
				Name:           "web",
				Index:          model.StringKey("a"),
				Module:         "module.net",
				Provider:       "registry.terraform.io/hashicorp/aws",
				ProviderConfig: "aws.eu",
				Values: map[string]any{
					"ingress": []any{map[string]any{"cidr_blocks": nil, "from_port": 443}},
				},
				Unknown:    []model.Path{{model.AttrStep("ingress"), model.IndexStep(0), model.AttrStep("cidr_blocks")}},
				Sensitive:  []model.Path{},
				References: map[string][]string{"ingress.0.cidr_blocks": {"module.net.aws_vpc.main"}},
				Meta: model.ResourceMeta{
					CountUnknown:   false,
					ForEachUnknown: true,
					DependsOn:      []string{"module.net.aws_vpc.main"},
					Lifecycle:      model.Lifecycle{PreventDestroy: &yes, IgnoreChanges: []string{"tags"}},
				},
				Source: model.ResourceSource{
					File:       "modules/net/sg.tf",
					Range:      model.Range{StartLine: 1, StartColumn: 1, EndLine: 9, EndColumn: 2},
					Attributes: map[string]model.Range{"ingress.0.cidr_blocks": {StartLine: 4, StartColumn: 5, EndLine: 4, EndColumn: 30}},
					ModuleCall: &loc,
				},
			},
			{
				Address:     "data.aws_iam_policy_document.admin[0]",
				BaseAddress: "data.aws_iam_policy_document.admin",
				Mode:        model.ModeData,
				Type:        "aws_iam_policy_document",
				Name:        "admin",
				Index:       model.IntKey(0),
				Provider:    "registry.terraform.io/hashicorp/aws",
				Source:      model.ResourceSource{File: "iam.tf", Range: model.Range{StartLine: 1, StartColumn: 1, EndLine: 2, EndColumn: 2}},
			},
		},
		ModuleCalls: []model.ModuleCall{
			{Address: "module.net", Source: "./modules/net", Resolved: true, SourceRange: loc},
			{Address: "module.vpc", Source: "terraform-aws-modules/vpc/aws", Version: "5.8.1", Reason: "remote module not in .terraform/modules", SourceRange: loc},
		},
		Variables:    []model.Variable{{Name: "db_password", Module: "module.net", Sensitive: true, Type: "string"}},
		Outputs:      []model.Output{{Name: "sg_id", Module: "", References: []string{"module.net.aws_security_group.web"}, SourceRange: loc}},
		CoverageGaps: []model.CoverageGap{{Kind: model.GapUnresolvedModule, Detail: "module.vpc", File: "main.tf", Line: 12}},
	}
}

func TestSchemaAcceptsEncodedDocuments(t *testing.T) {
	t.Parallel()
	s := compileSchema(t)
	tests := []struct {
		name string
		doc  *model.InputDocument
	}{
		{"every field set", fullDocument()},
		{"minimal document with nil collections", &model.InputDocument{
			SchemaVersion: model.InputSchemaVersion,
			Source:        model.DocumentSource{Kind: model.SourceHCL, RootModule: "."},
		}},
		{"resource with nil collections", &model.InputDocument{
			SchemaVersion: model.InputSchemaVersion,
			Source:        model.DocumentSource{Kind: model.SourceHCL, RootModule: "."},
			Resources: []model.Resource{{
				Address: "aws_s3_bucket.b", BaseAddress: "aws_s3_bucket.b", Mode: model.ModeManaged,
				Type: "aws_s3_bucket", Name: "b",
				Source: model.ResourceSource{File: "main.tf", Range: model.Range{StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 2}},
			}},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data, err := model.EncodeInput(tc.doc)
			if err != nil {
				t.Fatalf("EncodeInput: %v", err)
			}
			if err := validate(t, s, data); err != nil {
				t.Errorf("schema rejects the encoded document: %v\n%s", err, data)
			}
			back, err := model.DecodeInput(data)
			if err != nil {
				t.Fatalf("DecodeInput of encoded document: %v", err)
			}
			again, err := model.EncodeInput(back)
			if err != nil {
				t.Fatalf("EncodeInput after decode: %v", err)
			}
			if !bytes.Equal(data, again) {
				t.Errorf("encode/decode/encode is not stable:\nfirst:  %s\nsecond: %s", data, again)
			}
		})
	}
}

func TestEncodeInputNeverEmitsNullCollections(t *testing.T) {
	t.Parallel()
	data, err := model.EncodeInput(&model.InputDocument{SchemaVersion: model.InputSchemaVersion})
	if err != nil {
		t.Fatalf("EncodeInput: %v", err)
	}
	for _, field := range []string{"provider_versions", "providers", "resources", "module_calls", "variables", "outputs", "coverage_gaps", "required_providers"} {
		if bytes.Contains(data, []byte(`"`+field+`":null`)) {
			t.Errorf("%s is encoded as null: %s", field, data)
		}
	}
}

func TestEncodeInputIsDeterministic(t *testing.T) {
	t.Parallel()
	doc := fullDocument()
	for i := range 50 {
		doc.ProviderVersions[strings.Repeat("p", i+1)] = "1.0.0"
		doc.Resources[0].Values[strings.Repeat("v", i+1)] = i
	}
	first, err := model.EncodeInput(doc)
	if err != nil {
		t.Fatalf("EncodeInput: %v", err)
	}
	for range 20 {
		got, err := model.EncodeInput(doc)
		if err != nil {
			t.Fatalf("EncodeInput: %v", err)
		}
		if !bytes.Equal(first, got) {
			t.Fatalf("EncodeInput output differs between runs")
		}
	}
}

// mutate decodes the reference example, applies f to the generic value and re-encodes it.
func mutate(t *testing.T, f func(doc map[string]any)) []byte {
	t.Helper()
	doc, ok := semantic(t, readFile(t, "testdata/input-example.json")).(map[string]any)
	if !ok {
		t.Fatal("reference example is not an object")
	}
	f(doc)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode mutated example: %v", err)
	}
	return data
}

func resource0(doc map[string]any) map[string]any {
	return doc["resources"].([]any)[0].(map[string]any)
}

func TestSchemaRejectsMalformedDocuments(t *testing.T) {
	t.Parallel()
	s := compileSchema(t)
	tests := []struct {
		name string
		f    func(doc map[string]any)
	}{
		{"wrong schema version", func(d map[string]any) { d["schema_version"] = "2" }},
		{"missing resources", func(d map[string]any) { delete(d, "resources") }},
		{"null resources", func(d map[string]any) { d["resources"] = nil }},
		{"unknown top-level field", func(d map[string]any) { d["extra"] = true }},
		{"unknown source kind", func(d map[string]any) { d["source"].(map[string]any)["kind"] = "cdk" }},
		{"absolute root module", func(d map[string]any) { d["source"].(map[string]any)["root_module"] = "/etc" }},
		{"unknown resource mode", func(d map[string]any) { resource0(d)["mode"] = "ephemeral" }},
		{"unknown resource field", func(d map[string]any) { resource0(d)["extra"] = 1 }},
		{"fractional index", func(d map[string]any) { resource0(d)["index"] = 1.5 }},
		{"negative index", func(d map[string]any) { resource0(d)["index"] = -1 }},
		{"boolean path element", func(d map[string]any) { resource0(d)["unknown"] = []any{[]any{true}} }},
		{"empty path", func(d map[string]any) { resource0(d)["unknown"] = []any{[]any{}} }},
		{"path that is not an array", func(d map[string]any) { resource0(d)["sensitive"] = []any{"subnet_id"} }},
		{"references value not a list", func(d map[string]any) { resource0(d)["references"] = map[string]any{"subnet_id": "aws_subnet.private"} }},
		{"zero start line", func(d map[string]any) {
			resource0(d)["source"].(map[string]any)["range"].(map[string]any)["start_line"] = 0
		}},
		{"absolute source file", func(d map[string]any) { resource0(d)["source"].(map[string]any)["file"] = "/home/user/main.tf" }},
		{"backslash in source file", func(d map[string]any) { resource0(d)["source"].(map[string]any)["file"] = `infra\prod\compute.tf` }},
		{"parent escape in source file", func(d map[string]any) { resource0(d)["source"].(map[string]any)["file"] = "../outside/main.tf" }},
		{"unknown coverage gap kind", func(d map[string]any) {
			d["coverage_gaps"] = []any{map[string]any{"kind": "other", "detail": "x", "file": "main.tf", "line": 1}}
		}},
		{"variable with a value", func(d map[string]any) {
			d["variables"].([]any)[0].(map[string]any)["value"] = "prod"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := validate(t, s, mutate(t, tc.f)); err == nil {
				t.Errorf("schema accepts a document with %s", tc.name)
			}
		})
	}
}

func TestDecodeInputRejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"unknown field", mutate(t, func(d map[string]any) { d["extra"] = true }), "extra"},
		{"boolean path element", mutate(t, func(d map[string]any) { resource0(d)["unknown"] = []any{[]any{true}} }), "path element"},
		{"fractional path index", mutate(t, func(d map[string]any) { resource0(d)["unknown"] = []any{[]any{"a", 0.5}} }), "path element"},
		{"negative path index", mutate(t, func(d map[string]any) { resource0(d)["unknown"] = []any{[]any{"a", -1}} }), "path element"},
		{"fractional instance key", mutate(t, func(d map[string]any) { resource0(d)["index"] = 1.5 }), "instance key"},
		{"boolean instance key", mutate(t, func(d map[string]any) { resource0(d)["index"] = true }), "instance key"},
		{"wrong schema version", mutate(t, func(d map[string]any) { d["schema_version"] = "2" }), "schema_version"},
		{"not JSON", []byte(`{"schema_version":`), "decode input document"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := model.DecodeInput(tc.data)
			if err == nil {
				t.Fatal("DecodeInput succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestPathString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path model.Path
		want string
	}{
		{model.Path{model.AttrStep("subnet_id")}, "subnet_id"},
		{model.Path{model.AttrStep("ingress"), model.IndexStep(0), model.AttrStep("cidr_blocks")}, "ingress.0.cidr_blocks"},
		{model.Path{}, ""},
	}
	for _, tc := range tests {
		if got := tc.path.String(); got != tc.want {
			t.Errorf("%v.String() = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestInstanceKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		key  model.InstanceKey
		json string
	}{
		{"no key", model.NoKey, "null"},
		{"int key", model.IntKey(3), "3"},
		{"string key", model.StringKey(`a"b`), `"a\"b"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tc.key)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(data) != tc.json {
				t.Errorf("Marshal = %s, want %s", data, tc.json)
			}
			var back model.InstanceKey
			if err := json.Unmarshal(data, &back); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if back != tc.key {
				t.Errorf("Unmarshal(%s) = %#v, want %#v", data, back, tc.key)
			}
		})
	}
}

func TestPathStepAccessors(t *testing.T) {
	t.Parallel()
	attr, idx := model.AttrStep("tags"), model.IndexStep(2)
	if attr.IsIndex() || attr.Name() != "tags" || attr.Index() != 0 {
		t.Errorf("AttrStep(tags) = {IsIndex %v, Name %q, Index %d}", attr.IsIndex(), attr.Name(), attr.Index())
	}
	if !idx.IsIndex() || idx.Name() != "" || idx.Index() != 2 {
		t.Errorf("IndexStep(2) = {IsIndex %v, Name %q, Index %d}", idx.IsIndex(), idx.Name(), idx.Index())
	}
}

func TestInstanceKeyAccessors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		key   model.InstanceKey
		none  bool
		i     int
		isInt bool
		s     string
		isStr bool
	}{
		{"no key", model.NoKey, true, 0, false, "", false},
		{"int key", model.IntKey(4), false, 4, true, "", false},
		{"string key", model.StringKey("k"), false, 0, false, "k", true},
	}
	for _, tc := range tests {
		i, isInt := tc.key.Int()
		s, isStr := tc.key.Str()
		if tc.key.IsNone() != tc.none || i != tc.i || isInt != tc.isInt || s != tc.s || isStr != tc.isStr {
			t.Errorf("%s: IsNone %v, Int (%d, %v), Str (%q, %v)", tc.name, tc.key.IsNone(), i, isInt, s, isStr)
		}
	}
}

func TestEncodeInputRejectsNegativeIndexes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mut     func(r *model.Resource)
		wantErr string
	}{
		{"negative instance key", func(r *model.Resource) { r.Index = model.IntKey(-1) }, "instance key"},
		{"negative path index", func(r *model.Resource) {
			r.Unknown = []model.Path{{model.AttrStep("ingress"), model.IndexStep(-1)}}
		}, "path element"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := fullDocument()
			tc.mut(&doc.Resources[0])
			_, err := model.EncodeInput(doc)
			if err == nil {
				t.Fatal("EncodeInput succeeded, want an error")
			}
			if !strings.Contains(err.Error(), "encode input document") || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not name the document and %q", err, tc.wantErr)
			}
		})
	}
}

func TestValuesEncodeNilAsNull(t *testing.T) {
	t.Parallel()
	doc := &model.InputDocument{
		SchemaVersion: model.InputSchemaVersion,
		Source:        model.DocumentSource{Kind: model.SourceHCL, RootModule: "."},
		Resources: []model.Resource{{
			Address: "aws_s3_bucket.b", BaseAddress: "aws_s3_bucket.b", Mode: model.ModeManaged,
			Type: "aws_s3_bucket", Name: "b",
			Values: model.Values{
				"cidr_blocks": []any(nil),
				"tags":        map[string]any(nil),
				"ingress":     []any{map[string]any{"ports": []any(nil)}},
				"versioning":  []any{},
			},
			Source: model.ResourceSource{File: "main.tf", Range: model.Range{StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 2}},
		}},
	}
	data, err := model.EncodeInput(doc)
	if err != nil {
		t.Fatalf("EncodeInput: %v", err)
	}
	for _, want := range []string{`"cidr_blocks":null`, `"tags":null`, `"ports":null`, `"versioning":[]`} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("encoded values lack %s: %s", want, data)
		}
	}

	empty, err := json.Marshal(model.Values(nil))
	if err != nil {
		t.Fatalf("Marshal nil Values: %v", err)
	}
	if string(empty) != "{}" {
		t.Errorf("nil Values encodes as %s, want {}", empty)
	}
}

func TestDecodeInputErrorsDoNotQuoteValues(t *testing.T) {
	t.Parallel()
	const secret = "fake-secret-value"
	tests := []struct {
		name string
		f    func(d map[string]any)
	}{
		{"object instance key", func(d map[string]any) { resource0(d)["index"] = map[string]any{"password": secret} }},
		{"object path element", func(d map[string]any) {
			resource0(d)["unknown"] = []any{[]any{map[string]any{"token": secret}}}
		}},
		{"schema version", func(d map[string]any) { d["schema_version"] = secret }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := model.DecodeInput(mutate(t, tc.f))
			if err == nil {
				t.Fatal("DecodeInput succeeded, want an error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error quotes the rejected value: %v", err)
			}
		})
	}
}

func TestSchemaTiesPlanFileToPlanMode(t *testing.T) {
	t.Parallel()
	s := compileSchema(t)
	tests := []struct {
		name string
		src  map[string]any
	}{
		{"plan mode without plan_file", map[string]any{"kind": "plan", "root_module": "."}},
		{"hcl mode with plan_file", map[string]any{"kind": "hcl", "root_module": ".", "plan_file": "plan.json"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := validate(t, s, mutate(t, func(d map[string]any) { d["source"] = tc.src })); err == nil {
				t.Errorf("schema accepts %s", tc.name)
			}
		})
	}
}

// TestExampleMatchesReference keeps testdata/input-example.json identical to the example in the
// contract's reference document, so the schema test always checks the published example.
func TestExampleMatchesReference(t *testing.T) {
	t.Parallel()
	const reference = "../../.claude/skills/iace-architecture/references/input-document.md"
	doc := string(readFile(t, reference))
	start := strings.Index(doc, "```json\n")
	if start < 0 {
		t.Fatalf("%s has no json example", reference)
	}
	body := doc[start+len("```json\n"):]
	end := strings.Index(body, "```")
	if end < 0 {
		t.Fatalf("%s: unterminated json example", reference)
	}
	want := semantic(t, []byte(body[:end]))
	if diff := cmp.Diff(want, semantic(t, readFile(t, "testdata/input-example.json"))); diff != "" {
		t.Errorf("testdata/input-example.json differs from the example in %s (-reference +testdata):\n%s", reference, diff)
	}
}
