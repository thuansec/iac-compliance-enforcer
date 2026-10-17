package terraform_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// inputSchema compiles schemas/input.v1.json once per test.
func inputSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "schemas", "input.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(model.InputSchemaID, raw); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(model.InputSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// documents evaluates every root of dir and normalizes each into an encoded input document,
// checking that each validates against the schema.
func documents(t *testing.T, dir string) ([]*model.InputDocument, []terraform.Unexpressed) {
	t.Helper()
	results, err := evaluateRoots(context.Background(), t, dir)
	if err != nil {
		t.Fatalf("EvaluateRoots: %v", err)
	}
	schema := inputSchema(t)
	var docs []*model.InputDocument
	var notes []terraform.Unexpressed
	for _, rr := range results {
		doc, unexpressed := terraform.NormalizeRoot(rr)
		data, err := model.EncodeInput(doc)
		if err != nil {
			t.Fatalf("%s: encode: %v", rr.Dir, err)
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(inst); err != nil {
			t.Fatalf("%s: document does not validate: %v\n%s", rr.Dir, err, data)
		}
		docs, notes = append(docs, doc), append(notes, unexpressed)
	}
	return docs, notes
}

func section(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

var documentFixture = map[string]string{
	"main.tf": `terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }

  backend "s3" {
    bucket  = "tf-state"
    encrypt = true
    key     = "${var.env}/state"
  }
}

provider "aws" {
  region = var.region

  assume_role {
    role_arn = "arn:aws:iam::123456789012:role/fake"
  }
}

variable "env" {
  type    = string
  default = "prod"
}

variable "region" {
  type = string
}

module "app" {
  source = "./app"
  prefix = var.env
}

module "unused" {
  source = "./unused"
  count  = 0
}

module "remote" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.0"
}

resource "aws_s3_bucket" "root" {
  bucket = "root"
}

output "logs" {
  value     = module.app.bucket
  sensitive = true
}
`,
	".terraform.lock.hcl": `provider "registry.terraform.io/hashicorp/aws" {
  version = "6.12.0"
}
`,
	"app/main.tf": `variable "prefix" {
  type = string
}

resource "aws_s3_bucket" "logs" {
  bucket = "${var.prefix}-logs"
}

output "bucket" {
  value = aws_s3_bucket.logs.id
}
`,
	"unused/main.tf": `resource "aws_s3_bucket" "orphan" {
  bucket = "orphan"
}
`,
}

func TestNormalizeRoot(t *testing.T) {
	docs, notes := documents(t, files(t, documentFixture))
	if len(docs) != 2 {
		t.Fatalf("%d documents, want the root and the orphan", len(docs))
	}
	root := docs[0]
	for _, tc := range []struct {
		name string
		got  any
		want string
	}{
		{"source", root.Source, `{"kind":"hcl","root_module":"."}`},
		{"terraform", root.Terraform, `{"required_version":">= 1.6",` +
			`"backend":{"type":"s3","values":{"bucket":"tf-state","encrypt":true,"key":null},"unknown":[["key"]]},` +
			`"required_providers":{"aws":{"source":"registry.terraform.io/hashicorp/aws","version":"~> 6.0"}}}`},
		{"provider_versions", root.ProviderVersions, `{"registry.terraform.io/hashicorp/aws":"6.12.0"}`},
		{"providers", root.Providers, `[{"local_name":"aws","alias":"","source":"registry.terraform.io/hashicorp/aws",` +
			`"values":{"assume_role":null,"region":null},"unknown":[["assume_role"],["region"]],"sensitive":[],` +
			`"source_range":{"file":"main.tf","range":{"start_line":15,"start_column":1,"end_line":21,"end_column":2}}}]`},
		{"module_calls", root.ModuleCalls, `[` +
			`{"address":"module.app","source":"./app","version":"","resolved":true,"reason":"",` +
			`"source_range":{"file":"main.tf","range":{"start_line":32,"start_column":1,"end_line":35,"end_column":2}}},` +
			`{"address":"module.remote","source":"terraform-aws-modules/s3-bucket/aws","version":"4.1.0","resolved":false,"reason":"remote_source",` +
			`"source_range":{"file":"main.tf","range":{"start_line":42,"start_column":1,"end_line":45,"end_column":2}}},` +
			`{"address":"module.unused","source":"./unused","version":"","resolved":true,"reason":"",` +
			`"source_range":{"file":"main.tf","range":{"start_line":37,"start_column":1,"end_line":40,"end_column":2}}}]`},
		{"variables", root.Variables, `[` +
			`{"name":"env","module":"","sensitive":false,"has_default":true,"type":"string"},` +
			`{"name":"region","module":"","sensitive":false,"has_default":false,"type":"string"},` +
			`{"name":"prefix","module":"module.app","sensitive":false,"has_default":false,"type":"string"}]`},
		{"outputs", root.Outputs, `[` +
			// References stop at a module's outputs: the contract follows locals and module inputs.
			`{"name":"logs","module":"","sensitive":true,"references":["module.app"],` +
			`"source_range":{"file":"main.tf","range":{"start_line":51,"start_column":1,"end_line":51,"end_column":14}}},` +
			`{"name":"bucket","module":"module.app","sensitive":false,"references":["module.app.aws_s3_bucket.logs"],` +
			`"source_range":{"file":"app/main.tf","range":{"start_line":9,"start_column":1,"end_line":9,"end_column":16}}}]`},
	} {
		if s := section(t, tc.got); s != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, s, tc.want)
		}
	}
	var addresses []string
	for _, r := range root.Resources {
		addresses = append(addresses, r.Address)
	}
	if got, want := strings.Join(addresses, " "), "aws_s3_bucket.root module.app.aws_s3_bucket.logs"; got != want {
		t.Errorf("resources %q, want %q", got, want)
	}
	if section(t, notes[0]) != `{"incomplete_resources":[],"incomplete_references":[]}` {
		t.Errorf("unexpressed %s, want none", section(t, notes[0]))
	}

	orphan := docs[1]
	if orphan.Source.RootModule != "unused" || len(orphan.Resources) != 1 || orphan.Resources[0].Address != "aws_s3_bucket.orphan" {
		t.Errorf("orphan document: root %q, resources %v", orphan.Source.RootModule, orphan.Resources)
	}
	if orphan.Terraform.Backend != nil || orphan.Terraform.RequiredVersion != "" {
		t.Errorf("orphan terraform settings %s, want none", section(t, orphan.Terraform))
	}
}

func TestNormalizeRootIsDeterministic(t *testing.T) {
	dir := files(t, documentFixture)
	encodeAll := func() string {
		docs, _ := documents(t, dir)
		var b strings.Builder
		for _, d := range docs {
			data, err := model.EncodeInput(d)
			if err != nil {
				t.Fatal(err)
			}
			b.Write(data)
		}
		return b.String()
	}
	first := encodeAll()
	for range 3 {
		if again := encodeAll(); again != first {
			t.Fatal("documents differ between runs")
		}
	}
}

func TestNormalizeRootReportsWhatItCannotExpress(t *testing.T) {
	docs, notes := documents(t, files(t, map[string]string{
		"main.tf": `variable "u" {
  type = string
}

resource "aws_security_group" "web" {
  names = [` + strings.Repeat("var.u, ", 1100) + `]
}

resource "aws_s3_bucket" "ok" {
  bucket = "ok"
}
`,
	}))
	if got := section(t, notes[0].IncompleteResources); got != `["aws_security_group.web"]` {
		t.Errorf("incomplete resources %s", got)
	}
	// The incomplete resource is still listed, so later stages can report it.
	if len(docs[0].Resources) != 2 {
		t.Errorf("%d resources, want 2", len(docs[0].Resources))
	}
}

func TestNormalizeRootReadsJSONSettings(t *testing.T) {
	docs, _ := documents(t, files(t, map[string]string{
		"main.tf.json": `{
  "terraform": {
    "required_version": ">= 1.7",
    "backend": {"azurerm": {"container_name": "tfstate", "use_oidc": true, "snapshot": 3, "key": "${var.k}", "nested": {"a": 1}}}
  },
  "provider": {"azurerm": {"features": {}, "subscription_id": "00000000-0000-0000-0000-000000000000", "alias": "other"}}
}`,
	}))
	if got, want := section(t, docs[0].Terraform.Backend),
		`{"type":"azurerm","values":{"container_name":"tfstate","key":null,"nested":null,"snapshot":3,"use_oidc":true},"unknown":[["key"],["nested"]]}`; got != want {
		t.Errorf("backend:\n got %s\nwant %s", got, want)
	}
	if got := docs[0].Terraform.RequiredVersion; got != ">= 1.7" {
		t.Errorf("required_version %q", got)
	}
	p := docs[0].Providers[0]
	if got, want := section(t, []any{p.Alias, p.Values, p.Unknown}),
		`["other",{"features":null,"subscription_id":null},[["features"],["subscription_id"]]]`; got != want {
		t.Errorf("provider:\n got %s\nwant %s", got, want)
	}
}

// TestNormalizeRootListsEveryProviderSetting covers provider bodies that override files merge
// and dynamic blocks, which must never read as absent (T-0109c review).
func TestNormalizeRootListsEveryProviderSetting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"override replaces an attribute", map[string]string{
			"main.tf":     "provider \"aws\" {\n  region = \"x\"\n  assume_role {\n    role_arn = \"a\"\n  }\n}\n",
			"override.tf": "provider \"aws\" {\n  region = \"y\"\n}\n",
		}, `[["assume_role"],["region"]]`},
		{"only the override sets a block", map[string]string{
			"main.tf":     "provider \"aws\" {\n  region = \"x\"\n}\n",
			"override.tf": "provider \"aws\" {\n  assume_role {\n    role_arn = \"a\"\n  }\n}\n",
		}, `[["assume_role"],["region"]]`},
		{"JSON override", map[string]string{
			"main.tf":               "provider \"aws\" {\n  region = \"x\"\n  assume_role {\n    role_arn = \"a\"\n  }\n}\n",
			"main_override.tf.json": `{"provider": {"aws": {"default_tags": {"tags": {}}}}}`,
		}, `[["assume_role"],["default_tags"],["region"]]`},
		{"dynamic block", map[string]string{
			"main.tf": "variable \"roles\" {\n  type = list(string)\n}\n\nprovider \"aws\" {\n  dynamic \"assume_role\" {\n    for_each = var.roles\n    content {\n      role_arn = assume_role.value\n    }\n  }\n}\n",
		}, `[["assume_role"]]`},
		{"JSON dynamic block", map[string]string{
			"main.tf.json": `{"provider": {"aws": {"dynamic": {"assume_role": {"for_each": "${var.roles}", "content": {}}}}}}`,
		}, `[["assume_role"]]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docs, _ := documents(t, files(t, tc.files))
			if got := section(t, docs[0].Providers[0].Unknown); got != tc.want {
				t.Errorf("unknown %s, want %s", got, tc.want)
			}
		})
	}
}

func TestNormalizeRootJoinsRequiredVersions(t *testing.T) {
	docs, _ := documents(t, files(t, map[string]string{
		"a.tf": "terraform {\n  required_version = \">= 1.6\"\n}\n",
		"b.tf": "terraform {\n  required_version = \"< 2.0\"\n}\n",
	}))
	if got := docs[0].Terraform.RequiredVersion; got != ">= 1.6, < 2.0" {
		t.Errorf("required_version %q", got)
	}
}

func TestNormalizeRootCoversEveryInstance(t *testing.T) {
	docs, _ := documents(t, files(t, map[string]string{
		"main.tf": "module \"x\" {\n  source = \"./x\"\n  count  = 2\n  n      = count.index\n}\n",
		"x/main.tf": "variable \"n\" {\n  type = number\n}\n\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"b-${var.n}\"\n}\n\n" +
			"output \"id\" {\n  value = aws_s3_bucket.b.id\n}\n",
	}))
	var got []string
	for _, r := range docs[0].Resources {
		got = append(got, r.Address+"="+section(t, r.Values["bucket"]))
	}
	for _, v := range docs[0].Variables {
		got = append(got, v.Module+".var."+v.Name)
	}
	for _, o := range docs[0].Outputs {
		got = append(got, o.Module+".output."+o.Name)
	}
	want := `module.x[0].aws_s3_bucket.b="b-0" module.x[1].aws_s3_bucket.b="b-1" ` +
		`module.x[0].var.n module.x[1].var.n module.x[0].output.id module.x[1].output.id`
	if s := strings.Join(got, " "); s != want {
		t.Errorf("got  %s\nwant %s", s, want)
	}
}

// TestNormalizeRootIsLinearInProviders bounds the work for many provider blocks: finding each
// block's body by scanning every block took 27.7 s for 40,000 of them (T-0109c review).
func TestNormalizeRootIsLinearInProviders(t *testing.T) {
	// Twenty files keep each under the 1 MiB file limit.
	contents := map[string]string{}
	for f := range 20 {
		var b strings.Builder
		for i := range 2_000 {
			fmt.Fprintf(&b, "provider \"aws\" {\n  alias  = \"p%d_%d\"\n  region = \"x\"\n}\n", f, i)
		}
		contents[fmt.Sprintf("p%02d.tf", f)] = b.String()
	}
	results, err := evaluateRoots(context.Background(), t, files(t, contents))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("%d roots, want 1", len(results))
	}
	start := time.Now()
	doc, _ := terraform.NormalizeRoot(results[0])
	if d := time.Since(start); d > 2*time.Second*raceSlowdown {
		t.Errorf("normalizing 40,000 provider blocks took %v", d)
	}
	if len(doc.Providers) != 40_000 {
		t.Errorf("%d providers", len(doc.Providers))
	}
}
