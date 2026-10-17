package terraform_test

import (
	"encoding/json/v2"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// normalized evaluates the module tree in dir and normalizes every resource of every instance,
// keyed by address.
func normalized(t *testing.T, dir string) map[string]model.Resource {
	t.Helper()
	out := map[string]model.Resource{}
	for _, inst := range mustEvaluateTree(t, dir) {
		for _, r := range inst.Resources {
			res, complete := terraform.NormalizeResource(r)
			if !complete {
				t.Fatalf("%s: values not normalized", r.Address)
			}
			out[res.Address] = res
		}
	}
	return out
}

func encode(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(data)
}

func TestNormalizeResourceFields(t *testing.T) {
	dir := files(t, map[string]string{
		"main.tf": `terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

provider "aws" {
  alias  = "eu"
  region = "eu-west-1"
}

variable "subnet" {
  type = string
}

variable "password" {
  type      = string
  sensitive = true
  default   = "fake-password-for-tests"
}

resource "aws_subnet" "private" {
  vpc_id = "vpc-0123"
}

resource "aws_instance" "web" {
  count    = 2
  provider = aws.eu

  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  subnet_id     = var.subnet
  private_ip    = aws_subnet.private.id
  user_data     = var.password
  tags          = { Name = "web-${count.index}" }

  metadata_options {
    http_tokens = "optional"
  }

  depends_on = [aws_subnet.private]

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [tags]
  }
}
`,
	})
	got := normalized(t, dir)
	web, ok := got["aws_instance.web[1]"]
	if !ok {
		t.Fatalf("aws_instance.web[1] missing; got %v", slices.Sorted(maps.Keys(got)))
	}
	// Ranges are checked separately; blank them so the expectation stays readable.
	web.Source.Range = model.Range{}
	web.Source.Attributes = nil
	want := `{"address":"aws_instance.web[1]","base_address":"aws_instance.web","mode":"managed",` +
		`"type":"aws_instance","name":"web","index":1,"module":"",` +
		`"provider":"registry.terraform.io/hashicorp/aws","provider_config":"aws.eu",` +
		`"values":{"ami":"ami-0123456789abcdef0","instance_type":"t3.micro",` +
		`"metadata_options":[{"http_tokens":"optional"}],"private_ip":null,"subnet_id":null,` +
		`"tags":{"Name":"web-1"},"user_data":"fake-password-for-tests"},` +
		`"unknown":[["private_ip"],["subnet_id"]],"sensitive":[["user_data"]],` +
		`"references":{"private_ip":["aws_subnet.private"]},` +
		`"meta":{"count_unknown":false,"for_each_unknown":false,"depends_on":["aws_subnet.private"],` +
		`"lifecycle":{"prevent_destroy":true,"ignore_changes":["tags"]}},` +
		`"source":{"file":"main.tf","range":{"start_line":0,"start_column":0,"end_line":0,"end_column":0},"attributes":{}}}`
	if s := encode(t, web); s != want {
		t.Errorf("aws_instance.web[1]:\n got %s\nwant %s", s, want)
	}
}

func TestNormalizeResourceSourceRanges(t *testing.T) {
	dir := files(t, map[string]string{
		"main.tf": `module "app" {
  source = "./app"
}
`,
		"app/main.tf": `resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
`,
	})
	got := normalized(t, dir)
	b, ok := got["module.app.aws_s3_bucket.logs"]
	if !ok {
		t.Fatal("module.app.aws_s3_bucket.logs missing")
	}
	if b.Module != "module.app" || b.BaseAddress != "module.app.aws_s3_bucket.logs" {
		t.Errorf("module %q base %q", b.Module, b.BaseAddress)
	}
	want := `{"file":"app/main.tf","range":{"start_line":1,"start_column":1,"end_line":3,"end_column":2},` +
		`"attributes":{"bucket":{"start_line":2,"start_column":12,"end_line":2,"end_column":18}},` +
		`"module_call":{"file":"main.tf","range":{"start_line":1,"start_column":1,"end_line":1,"end_column":13}}}`
	if s := encode(t, b.Source); s != want {
		t.Errorf("source:\n got %s\nwant %s", s, want)
	}
}

func TestNormalizeResourceValues(t *testing.T) {
	dir := files(t, map[string]string{
		"main.tf": `variable "unset" {
  type = string
}

resource "x_thing" "t" {
  int_exact   = 9007199254740993
  negative    = -42
  fraction    = 0.1
  large       = 1e300
  too_large   = 1e400
  too_small   = 1e-400
  zero        = 0
  explicit    = null
  list        = ["a", var.unset]
  set_known   = toset(["b", "a"])
  set_unknown = toset(["a", var.unset])
  map         = { "key with space" = 1, other = var.unset }
  nested {
    inner {
      deep = var.unset
    }
  }
  nested {
    inner {
      deep = "known"
    }
  }
}
`,
	})
	r := normalized(t, dir)["x_thing.t"]
	want := `{"fraction":0.1,"int_exact":9007199254740993,"large":1e+300,` +
		`"list":["a",null],"map":{"key with space":1,"other":null},` +
		`"negative":-42,"nested":[{"inner":[{"deep":null}]},{"inner":[{"deep":"known"}]}],` +
		`"set_known":["a","b"],"set_unknown":null,"too_large":null,"too_small":null,"zero":0}`
	if s := encode(t, r.Values); s != want {
		t.Errorf("values:\n got %s\nwant %s", s, want)
	}
	wantUnknown := `[["list",1],["map","other"],["nested",0,"inner",0,"deep"],["set_unknown"],["too_large"],["too_small"]]`
	if s := encode(t, r.Unknown); s != wantUnknown {
		t.Errorf("unknown:\n got %s\nwant %s", s, wantUnknown)
	}
}

func TestNormalizeResourceIsDeterministic(t *testing.T) {
	dir := files(t, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "a" {
  bucket = "a"
}

resource "aws_s3_bucket" "b" {
  bucket = "b"
}

resource "aws_s3_bucket_policy" "p" {
  bucket = aws_s3_bucket.b.id
  policy = jsonencode({ a = aws_s3_bucket.a.arn, b = aws_s3_bucket.b.arn, z = 1, y = 2 })
}
`,
	})
	first := encode(t, normalized(t, dir)["aws_s3_bucket_policy.p"])
	for range 5 {
		if again := encode(t, normalized(t, dir)["aws_s3_bucket_policy.p"]); again != first {
			t.Fatalf("not deterministic:\n%s\n%s", first, again)
		}
	}
	r := normalized(t, dir)["aws_s3_bucket_policy.p"]
	if got := r.References["policy"]; !slices.IsSorted(got) || len(got) != 2 {
		t.Errorf("policy references %v, want two sorted addresses", got)
	}
}

// TestNormalizeManyUnknownsWithADynamicBlock covers the evaluator collapsing more than 1024
// unknown paths into the whole value: the dynamic block's unknown number of entries must not
// come out as one known entry (T-0109 review).
func TestNormalizeManyUnknownsWithADynamicBlock(t *testing.T) {
	dir := files(t, map[string]string{
		"main.tf": `variable "u" {
  type = string
}

variable "rules" {
  type = list(number)
}

resource "aws_security_group" "web" {
  names = [` + strings.Repeat("var.u, ", 1100) + `]

  dynamic "ingress" {
    for_each = var.rules
    content {
      from_port   = ingress.value
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
`,
	})
	found := false
	for _, inst := range mustEvaluateTree(t, dir) {
		for _, r := range inst.Resources {
			if r.Address != "aws_security_group.web" {
				continue
			}
			found = true
			// Over 1024 unknowns collapse into the whole value, which no path can express: the
			// resource is incomplete, so the caller reports it as a coverage gap.
			if got, complete := terraform.NormalizeResource(r); complete {
				t.Errorf("complete, ingress = %v, unknown = %v", got.Values["ingress"], got.Unknown)
			}
		}
	}
	if !found {
		t.Fatal("aws_security_group.web was not evaluated")
	}
}
