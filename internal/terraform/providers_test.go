package terraform_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

func TestResourcesMapToProviderSources(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": `terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    awsalt = {
      source = "hashicorp/aws"
    }
    corp = {
      source = "Example.COM/Acme/Corp"
    }
    legacy = "~> 1.0"
    bad = {
      source = "a/b/c/d"
    }
    quoted = {
      "source" = "acme/quoted"
    }
    tmpl = {
      source = "acme/${"x"}"
    }
    weird = 5
  }
}
provider "aws" {
  region = "eu-west-1"
}
provider "aws" {
  alias  = "us"
  region = "us-east-1"
}
resource "aws_s3_bucket" "a" {}
resource "aws_s3_bucket" "b" {
  provider = aws.us
}
resource "aws_s3_bucket" "c" {
  provider = awsalt
}
resource "corp_thing" "d" {}
resource "google_storage_bucket" "e" {}
resource "legacy_x" "f" {}
resource "bad_x" "g" {}
resource "quoted_x" "q" {}
resource "tmpl_x" "t" {}
resource "weird_x" "w" {}
resource "terraform_data" "td" {}
module "child" {
  source = "./child"
}
`,
		"child/main.tf": `terraform {
  required_providers {
    aws = {
      source = "custom/aws"
    }
  }
}
resource "aws_s3_bucket" "h" {}
`,
	})
	instances := mustEvaluateTree(t, dir)
	got := map[string]string{}
	for _, inst := range instances {
		for _, r := range inst.Resources {
			got[r.Address] = r.Provider + " " + r.ProviderConfig
		}
	}
	want := map[string]string{
		"aws_s3_bucket.a":              "registry.terraform.io/hashicorp/aws ",
		"aws_s3_bucket.b":              "registry.terraform.io/hashicorp/aws aws.us",
		"aws_s3_bucket.c":              "registry.terraform.io/hashicorp/aws awsalt",
		"corp_thing.d":                 "example.com/acme/corp ",
		"google_storage_bucket.e":      "registry.terraform.io/hashicorp/google ",
		"legacy_x.f":                   "registry.terraform.io/hashicorp/legacy ",
		"bad_x.g":                      " ",
		"quoted_x.q":                   "registry.terraform.io/acme/quoted ",
		"tmpl_x.t":                     " ",
		"weird_x.w":                    " ",
		"terraform_data.td":            "terraform.io/builtin/terraform ",
		"module.child.aws_s3_bucket.h": "registry.terraform.io/custom/aws ",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("providers (-want +got):\n%s", diff)
	}
	root := instances[0]
	req := root.Module.RequiredProviders()
	if r := req["aws"]; r.Source != "registry.terraform.io/hashicorp/aws" || r.Version != "~> 6.0" {
		t.Errorf("required aws = %+v", r)
	}
	if r := req["legacy"]; r.Source != "registry.terraform.io/hashicorp/legacy" || r.Version != "~> 1.0" {
		t.Errorf("required legacy = %+v", r)
	}
	var configs []string
	for _, p := range root.Providers {
		configs = append(configs, p.LocalName+" "+p.Alias+" "+p.Source)
	}
	if diff := cmp.Diff([]string{"aws  registry.terraform.io/hashicorp/aws", "aws us registry.terraform.io/hashicorp/aws"}, configs); diff != "" {
		t.Errorf("provider configs (-want +got):\n%s", diff)
	}
	// bad (line 15), the template source (line 21) and the number entry (line 23) are reported.
	for _, line := range []int{15, 21, 23} {
		if !slices.ContainsFunc(root.Module.Diagnostics, func(d terraform.Diagnostic) bool {
			return d.Code == terraform.DiagInvalidProviderSource && d.Line == line
		}) {
			t.Errorf("no invalid_provider_source warning at line %d: %v", line, diagLines(root.Module))
		}
	}
}

func readLock(t *testing.T, content string) (map[string]string, []terraform.Diagnostic) {
	t.Helper()
	contents := map[string]string{"main.tf": ""}
	if content != "" {
		contents[".terraform.lock.hcl"] = content
	}
	dir := files(t, contents)
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return terraform.ReadLockFile(r, ".")
}

func TestReadLockFile(t *testing.T) {
	t.Parallel()
	versions, diags := readLock(t, `# This file is maintained automatically by "terraform init".
provider "registry.terraform.io/hashicorp/aws" {
  version     = "6.12.0"
  constraints = "~> 6.0"
  hashes = [
    "h1:fake-hash-value=",
  ]
}
provider "registry.terraform.io/hashicorp/random" {
  version = "3.6.3"
}
`)
	want := map[string]string{
		"registry.terraform.io/hashicorp/aws":    "6.12.0",
		"registry.terraform.io/hashicorp/random": "3.6.3",
	}
	if diff := cmp.Diff(want, versions); diff != "" || len(diags) != 0 {
		t.Errorf("versions (-want +got):\n%s\ndiagnostics %v", diff, diags)
	}
	if v, d := readLock(t, ""); len(v) != 0 || len(d) != 0 {
		t.Errorf("no lock file: %v %v", v, d)
	}
}

func TestReadLockFileRejectsWhatItCannotTrust(t *testing.T) {
	t.Parallel()
	for name, content := range map[string]string{
		"syntax":        `provider "x" {`,
		"not literal":   "provider \"registry.terraform.io/hashicorp/aws\" {\n  version = var.v\n}\n",
		"bad address":   "provider \"not an address\" {\n  version = \"1.0.0\"\n}\n",
		"duplicate":     "provider \"registry.terraform.io/a/b\" {\n  version = \"1.0.0\"\n}\nprovider \"registry.terraform.io/a/b\" {\n  version = \"2.0.0\"\n}\n",
		"not a version": "provider \"registry.terraform.io/a/b\" {\n  version = \"abc\"\n}\n",
		"two labels":    "provider \"registry.terraform.io/a/b\" \"x\" {\n  version = \"1.0.0\"\n}\n",
		"too large":     "# " + strings.Repeat("x", 1<<20) + "\n",
		// Well-formed but nested past the guard's 512 levels: refused before hcl parses it.
		"deep nesting": "provider \"registry.terraform.io/a/b\" {\n  version = " + strings.Repeat("[", 600) + strings.Repeat("]", 600) + "\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			versions, diags := readLock(t, content)
			if len(diags) == 0 || !slices.ContainsFunc(diags, func(d terraform.Diagnostic) bool {
				return d.Code == terraform.DiagLockFileInvalid
			}) {
				t.Errorf("diagnostics %v, want lock_file_invalid", diags)
			}
			want := map[string]string{}
			if name == "duplicate" {
				want["registry.terraform.io/a/b"] = "1.0.0" // the first is kept
			}
			if diff := cmp.Diff(want, versions); diff != "" {
				t.Errorf("versions (-want +got):\n%s", diff)
			}
			if name == "deep nesting" && !slices.ContainsFunc(diags, func(d terraform.Diagnostic) bool {
				return strings.Contains(d.Summary, "nested too deeply")
			}) {
				t.Errorf("diagnostics %v, want the nesting guard's", diags)
			}
		})
	}
}

// EvaluateRoots reads each root's lock file into the result.
func TestRootsCarryLockedVersions(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":             "",
		".terraform.lock.hcl": "provider \"registry.terraform.io/hashicorp/aws\" {\n  version = \"6.12.0\"\n}\n",
	})
	results, err := evaluateRoots(context.Background(), t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if v := results[0].ProviderVersions["registry.terraform.io/hashicorp/aws"]; v != "6.12.0" {
		t.Errorf("ProviderVersions = %v", results[0].ProviderVersions)
	}
}

// The lock file's size cap, at and just below 1 MiB: both are read.
func TestLockFileSizeBoundary(t *testing.T) {
	t.Parallel()
	entry := "provider \"registry.terraform.io/a/b\" {\n  version = \"1.0.0-beta1\"\n}\n"
	for _, size := range []int{1<<20 - 1, 1 << 20} {
		pad := size - len(entry) - 3
		versions, diags := readLock(t, "# "+strings.Repeat("x", pad)+"\n"+entry)
		if versions["registry.terraform.io/a/b"] != "1.0.0-beta1" || len(diags) != 0 {
			t.Errorf("%d bytes: versions %v, diagnostics %v", size, versions, diags)
		}
	}
}

// A lock file that is not a regular file is a warning, never a failed scan.
func TestLockFileThatIsADirectory(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{"main.tf": "", ".terraform.lock.hcl/x": ""})
	results, err := evaluateRoots(context.Background(), t, dir)
	if err != nil {
		t.Fatalf("EvaluateRoots: %v", err)
	}
	if !slices.ContainsFunc(results[0].Instances[0].Module.Diagnostics, func(d terraform.Diagnostic) bool {
		return d.Code == terraform.DiagLockFileInvalid
	}) || len(results[0].ProviderVersions) != 0 {
		t.Errorf("diagnostics %v, versions %v", diagLines(results[0].Instances[0].Module), results[0].ProviderVersions)
	}
}
