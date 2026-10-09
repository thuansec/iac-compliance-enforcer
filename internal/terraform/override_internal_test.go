package terraform

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// Override files merge into the blocks they name, as Terraform merges them (ADR 0019).
func TestOverridesMergeIntoTheirBlocks(t *testing.T) {
	t.Parallel()
	m := parseFilesModule(t, map[string]string{
		"main.tf": `
variable "v" {
  type    = string
  default = "base"
}
locals {
  a = "base"
  b = "kept"
}
output "o" {
  value       = local.a
  description = "kept"
}
`,
		// Applied in name order: b_override.tf wins over a_override.tf.
		"a_override.tf": `
variable "v" {
  default = "first"
}
`,
		"b_override.tf": `
variable "v" {
  default = "second"
}
locals {
  a = "override"
}
`,
		// A JSON override of an HCL block.
		"override.tf.json": `{"output": {"o": {"value": "${local.b}"}}}`,
	})
	if m.HasErrors() {
		t.Fatalf("diagnostics: %v", m.Diagnostics)
	}
	ctx := context.Background()
	vars, err := m.EvaluateVariables(ctx, m.root, VarOptions{}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if v := vars["v"]; !v.Value.RawEquals(cty.StringVal("second")) || v.Type != "string" {
		t.Errorf("variable v = %#v of type %q, want \"second\" of type string", v.Value, v.Type)
	}
	locals, err := m.EvaluateLocals(ctx, vars)
	if err != nil {
		t.Fatal(err)
	}
	if got := locals["a"].Value; !got.RawEquals(cty.StringVal("override")) {
		t.Errorf("local.a = %#v, want the override", got)
	}
	if got := locals["b"].Value; !got.RawEquals(cty.StringVal("kept")) {
		t.Errorf("local.b = %#v, want the base value", got)
	}
	attrs := blockAttrs(t, m, "output", "o")
	if got := attrs["value"].Expr.Range().Filename; got != "override.tf.json" {
		t.Errorf("output value comes from %s, want the JSON override", got)
	}
	if got := attrs["description"].Expr.Range().Filename; got != "main.tf" {
		t.Errorf("output description comes from %s, want main.tf", got)
	}
}

// A provider override names its block by name and alias; required_providers merges by provider
// name, and other terraform settings replace the base's.
func TestOverridesMergeProvidersAndSettings(t *testing.T) {
	t.Parallel()
	m := parseFilesModule(t, map[string]string{
		"main.tf": `
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random" }
  }
}
provider "aws" {
  region = "us-east-1"
}
provider "aws" {
  alias  = "west"
  region = "us-west-2"
}
`,
		"main_override.tf": `
terraform {
  required_version = ">= 1.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
provider "aws" {
  alias  = "west"
  region = "eu-west-1"
}
`,
	})
	if m.HasErrors() {
		t.Fatalf("diagnostics: %v", m.Diagnostics)
	}
	rp := m.RequiredProviders()
	if got := rp["aws"].Version; got != "~> 6.0" {
		t.Errorf("aws version %q, want the override's", got)
	}
	if _, ok := rp["random"]; !ok {
		t.Error("random, which the override does not name, was dropped")
	}
	var versions []string
	for _, b := range m.Blocks {
		if b.Type == "terraform" {
			content, _, _ := b.Body.PartialContent(settingsSchema)
			if a, ok := content.Attributes["required_version"]; ok {
				v, _ := literalString(a.Expr, false)
				versions = append(versions, v)
			}
		}
	}
	if !slices.Equal(versions, []string{">= 1.9"}) {
		t.Errorf("required_version %q, want only the override's", versions)
	}
	regions := map[string]string{}
	for _, b := range m.Blocks {
		if b.Type != "provider" {
			continue
		}
		attrs, _ := b.Body.JustAttributes()
		alias, region := "", ""
		if a, ok := attrs["alias"]; ok {
			alias, _ = literalString(a.Expr, false)
		}
		region, _ = literalString(attrs["region"].Expr, false)
		regions[alias] = region
	}
	if want := map[string]string{"": "us-east-1", "west": "eu-west-1"}; !maps.Equal(regions, want) {
		t.Errorf("provider regions %v, want %v", regions, want)
	}
	if got := len(m.ProviderConfigs()); got != 2 {
		t.Errorf("%d provider configurations, want 2", got)
	}
}

// Nested blocks of a type in an override replace all of the base's blocks of that type.
func TestOverrideReplacesNestedBlocksByType(t *testing.T) {
	t.Parallel()
	m := parseFilesModule(t, map[string]string{
		"main.tf": `
variable "v" {
  type = string
  validation {
    condition     = length(var.v) > 1
    error_message = "one"
  }
  validation {
    condition     = length(var.v) > 2
    error_message = "two"
  }
}
`,
		"override.tf": `
variable "v" {
  validation {
    condition     = length(var.v) > 3
    error_message = "three"
  }
}
`,
	})
	if m.HasErrors() {
		t.Fatalf("diagnostics: %v", m.Diagnostics)
	}
	schema := &hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "type", Required: true}},
		Blocks:     []hcl.BlockHeaderSchema{{Type: "validation"}},
	}
	for _, b := range m.Blocks {
		if b.Type != "variable" {
			continue
		}
		content, diags := b.Body.Content(schema)
		if diags.HasErrors() {
			t.Fatal(diags)
		}
		if len(content.Blocks) != 1 || content.Blocks[0].DefRange.Filename != "override.tf" {
			t.Errorf("validation blocks %v, want only the override's", content.Blocks)
		}
		if _, ok := content.Attributes["type"]; !ok {
			t.Error("the base's type was lost")
		}
	}
}

// An override of something no other file declares is an error, as in Terraform, and so is a
// moved block in an override file.
func TestOverridesWithoutBase(t *testing.T) {
	t.Parallel()
	m := parseFilesModule(t, map[string]string{
		"main.tf": "locals {\n  a = 1\n}\nresource \"aws_s3_bucket\" \"b\" {}\n",
		"main_override.tf": `
variable "missing" {
  default = 1
}
locals {
  a = 2
  z = 3
}
provider "aws" {
  alias = "nowhere"
}
resource "aws_s3_bucket" "nowhere" {
  acl = "public-read"
}
moved {
  from = aws_s3_bucket.a
  to   = aws_s3_bucket.b
}
`,
	})
	type at struct {
		code DiagCode
		line int
	}
	var got []at
	for _, d := range m.Diagnostics {
		got = append(got, at{d.Code, d.Line})
	}
	want := []at{
		{DiagOverrideWithoutBase, 2},
		{DiagOverrideWithoutBase, 7},
		{DiagOverrideWithoutBase, 9},
		{DiagOverrideWithoutBase, 12},
		{DiagOverrideUnsupported, 15},
	}
	if !slices.Equal(got, want) {
		t.Errorf("diagnostics %v, want %v", got, want)
	}
	if !m.HasErrors() {
		t.Error("an override without a base must make the module an error, as Terraform rejects it")
	}
	locals, err := m.EvaluateLocals(context.Background(), map[string]Variable{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := locals["z"]; ok {
		t.Error("an override local without a base was declared")
	}
	if got := locals["a"].Value; !got.RawEquals(cty.NumberIntVal(2)) {
		t.Errorf("local.a = %#v, want 2", got)
	}
}

func blockAttrs(t *testing.T, m *ParsedModule, typ string, labels ...string) hcl.Attributes {
	t.Helper()
	for _, b := range m.Blocks {
		if b.Type == typ && slices.Equal(b.Labels, labels) {
			attrs, diags := b.Body.JustAttributes()
			if diags.HasErrors() {
				t.Fatal(diags)
			}
			return attrs
		}
	}
	t.Fatalf("no %s block %v", typ, labels)
	return nil
}

// Merging is linear in the override blocks: a 1 MiB override file of one-line overrides of the
// same local, setting, provider or variable parses quickly (repeated masking made 2,000 locals
// overrides take 100 s; T-0112a review).
func TestOverrideMergingIsLinear(t *testing.T) {
	base := `
locals {
  a = 1
}
terraform {
  required_version = ">= 1.0"
}
provider "aws" {
  region = "us-east-1"
}
variable "v" {
  default = 1
}
`
	for name, block := range map[string]string{
		"locals":    "locals {\n  a = 2\n}\n",
		"terraform": "terraform {\n  required_version = \"1\"\n}\n",
		"provider":  "provider \"aws\" {\n  region = \"x\"\n}\n",
		"variable":  "variable \"v\" {\n  default = 2\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			override := strings.Repeat(block, (1<<20-64)/len(block))
			start := time.Now()
			m := parseFilesModule(t, map[string]string{"main.tf": base, "override.tf": override})
			if m.HasErrors() {
				t.Fatalf("diagnostics: %v", m.Diagnostics[:min(3, len(m.Diagnostics))])
			}
			_ = m.RequiredProviders()
			if _, err := m.EvaluateLocals(context.Background(), map[string]Variable{}); err != nil {
				t.Fatal(err)
			}
			_ = m.ProviderConfigs()
			if elapsed := time.Since(start); elapsed > 20*time.Second {
				t.Errorf("parsing and reading %d overrides took %v", strings.Count(override, "\n}\n"), elapsed)
			}
		})
	}
}

// Overrides compound in file order, JSON overrides merge like HCL ones, and a backend or cloud
// block replaces the base's backend and cloud.
func TestOverridesCompound(t *testing.T) {
	t.Parallel()
	m := parseFilesModule(t, map[string]string{
		"main.tf": `
locals {
  a = 1
}
terraform {
  backend "s3" {}
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}
`,
		"a_override.tf":      "locals {\n  a = 2\n}\nterraform {\n  cloud {}\n}\n",
		"b_override.tf.json": `{"locals": {"a": 3}, "terraform": {"required_providers": {"aws": {"source": "hashicorp/aws", "version": "~> 6.0"}}}}`,
	})
	if m.HasErrors() {
		t.Fatalf("diagnostics: %v", m.Diagnostics)
	}
	locals, err := m.EvaluateLocals(context.Background(), map[string]Variable{})
	if err != nil {
		t.Fatal(err)
	}
	if got := locals["a"].Value; !got.RawEquals(cty.NumberIntVal(3)) {
		t.Errorf("local.a = %#v, want the last override's 3", got)
	}
	if got := m.RequiredProviders()["aws"].Version; got != "~> 6.0" {
		t.Errorf("aws version %q, want the JSON override's", got)
	}
	var backends []string
	for _, b := range m.Blocks {
		if b.Type != "terraform" {
			continue
		}
		content, _, _ := b.Body.PartialContent(settingsSchema)
		for _, blk := range content.Blocks {
			if blk.Type == "backend" || blk.Type == "cloud" {
				backends = append(backends, blk.Type+"@"+blk.DefRange.Filename)
			}
		}
	}
	if !slices.Equal(backends, []string{"cloud@a_override.tf"}) {
		t.Errorf("backends %v, want only the override's cloud", backends)
	}
}

// Terraform rejects these modules, so iace does too: a duplicate base local (masking must not
// hide it), overrides of a module call or output without a base, and depends_on in a module or
// output override. A diagnostic from an override's part of a merged block names the override file.
func TestOverrideErrors(t *testing.T) {
	t.Parallel()
	m := parseFilesModule(t, map[string]string{
		"a.tf": "locals {\n  a = 1\n}\nmodule \"m\" {\n  source = \"./m\"\n}\noutput \"o\" {\n  value = 1\n}\nvariable \"v\" {}\n",
		"b.tf": "locals {\n  a = 2\n}\n",
		"override.tf": `locals {
  a = 3
}
module "missing" {
  source = "./x"
}
output "missing" {
  value = 1
}
module "m" {
  depends_on = []
}
output "o" {
  depends_on = []
}
variable "v" {
  type = strin
}
`,
	})
	if _, err := m.EvaluateVariables(context.Background(), m.root, VarOptions{}, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.EvaluateLocals(context.Background(), map[string]Variable{}); err != nil {
		t.Fatal(err)
	}
	type at struct {
		code DiagCode
		file string
		line int
	}
	var got []at
	for _, d := range m.Diagnostics {
		if d.Severity == SeverityError {
			got = append(got, at{d.Code, d.File, d.Line})
		}
	}
	want := []at{
		{DiagDuplicateLocal, "b.tf", 2},
		{DiagOverrideWithoutBase, "override.tf", 4},
		{DiagOverrideWithoutBase, "override.tf", 7},
		{DiagOverrideUnsupported, "override.tf", 11},
		{DiagOverrideUnsupported, "override.tf", 14},
		{DiagSyntax, "override.tf", 17},
	}
	if !slices.Equal(got, want) {
		t.Errorf("errors %v, want %v", got, want)
	}
}
