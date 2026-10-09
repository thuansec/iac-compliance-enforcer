package terraform_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

const manifestPath = ".terraform/modules/modules.json"

// loadTrusted loads the tree of dir with the module manifest trusted.
func loadTrusted(t *testing.T, dir, rootDir string) *terraform.ModuleTree {
	t.Helper()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	limits := terraform.DefaultLimits()
	d, err := terraform.Discover(context.Background(), r, limits)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := terraform.LoadModuleTree(context.Background(), r, d, rootDir, limits,
		terraform.TreeOptions{TrustModuleManifest: true})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func TestRemoteModulesResolveThroughTheManifest(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": "module \"consul\" {\n  source  = \"hashicorp/consul/aws\"\n  version = \"0.1.0\"\n}\n" +
			module("git", "git::https://example.com/net.git?ref=v1") +
			module("net", "./net") +
			module("missing", "hashicorp/nothere/aws"),
		"net/main.tf":                            module("inner", "hashicorp/inner/aws"),
		".terraform/modules/consul/main.tf":      module("sub", "./sub") + module("deep", "hashicorp/deep/aws"),
		".terraform/modules/consul/sub/main.tf":  `resource "aws_vpc" "v" {}`,
		".terraform/modules/consul.deep/main.tf": `resource "aws_vpc" "d" {}`,
		".terraform/modules/git/main.tf":         `resource "aws_vpc" "g" {}`,
		".terraform/modules/net.inner/main.tf":   `resource "aws_vpc" "i" {}`,
		manifestPath: `{"Modules":[
  {"Key":"","Source":"","Dir":"."},
  {"Key":"consul","Source":"registry.terraform.io/hashicorp/consul/aws","Version":"0.1.0","Dir":".terraform/modules/consul"},
  {"Key":"consul.sub","Source":"./sub","Dir":".terraform/modules/consul/sub"},
  {"Key":"consul.deep","Source":"registry.terraform.io/hashicorp/deep/aws","Version":"1.0.0","Dir":".terraform/modules/consul.deep"},
  {"Key":"git","Source":"git::https://example.com/net.git?ref=v1","Dir":".terraform/modules/git"},
  {"Key":"net","Source":"./net","Dir":"net"},
  {"Key":"net.inner","Source":"registry.terraform.io/hashicorp/inner/aws","Version":"2.0.0","Dir":".terraform/modules/net.inner"}
]}`,
	})
	tree := loadTrusted(t, dir, ".")
	want := []string{
		"module.consul .terraform/modules/consul",
		"module.consul.module.sub .terraform/modules/consul/sub",
		"module.consul.module.deep .terraform/modules/consul.deep",
		"module.git .terraform/modules/git",
		"module.net net",
		"module.net.module.inner .terraform/modules/net.inner",
		"module.missing !remote_source",
	}
	if diff := cmp.Diff(want, flatten(tree.Root)); diff != "" {
		t.Errorf("tree (-want +got):\n%s", diff)
	}
	if got := moduleDiags(tree, terraform.DiagModuleUnresolved); len(got) != 1 || !strings.HasPrefix(got[0], "main.tf:") {
		t.Errorf("module_unresolved = %v, want only module.missing", got)
	}
}

func TestManifestEntriesAreConfined(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf": module("up", "acme/up/aws") + module("gone", "acme/gone/aws") +
			module("file", "acme/file/aws") + module("stale", "acme/stale/aws") +
			module("abs", "acme/abs/aws") + module("drive", "acme/drive/aws") +
			module("empty", "acme/empty/aws") + module("short", "github.com/acme/short"),
		".terraform/modules/file.tf":       "",
		".terraform/modules/stale/main.tf": "",
		manifestPath: `{"Modules":[
  {"Key":"up","Source":"registry.terraform.io/acme/up/aws","Dir":"../outside"},
  {"Key":"gone","Source":"registry.terraform.io/acme/gone/aws","Dir":".terraform/modules/gone"},
  {"Key":"file","Source":"registry.terraform.io/acme/file/aws","Dir":".terraform/modules/file.tf"},
  {"Key":"stale","Source":"registry.terraform.io/acme/other/aws","Dir":".terraform/modules/stale"},
  {"Key":"abs","Source":"registry.terraform.io/acme/abs/aws","Dir":"/etc"},
  {"Key":"drive","Source":"registry.terraform.io/acme/drive/aws","Dir":"C:\\Windows"},
  {"Key":"empty","Source":"registry.terraform.io/acme/empty/aws","Dir":""},
  {"Key":"short","Source":"git::https://github.com/acme/short.git","Dir":".terraform/modules/stale"}
]}`,
	})
	tree := loadTrusted(t, dir, ".")
	want := []string{
		"module.up !outside_root",
		"module.gone !not_found",
		"module.file !not_found",
		"module.stale !stale_manifest",
		"module.abs !outside_root",
		"module.drive !outside_root",
		"module.empty !outside_root",
		// Terraform records github.com shorthand in its normalized git form, which iace does not
		// derive (ADR 0013): it fails closed.
		"module.short !stale_manifest",
	}
	if diff := cmp.Diff(want, flatten(tree.Root)); diff != "" {
		t.Errorf("tree (-want +got):\n%s", diff)
	}
}

func TestInvalidManifestsAreIgnoredWithAWarning(t *testing.T) {
	t.Parallel()
	entry := `{"Key":"m","Source":"registry.terraform.io/acme/m/aws","Dir":".terraform/modules/m"}`
	for name, manifest := range map[string]string{
		"syntax":        `{"Modules":[`,
		"trailing data": `{"Modules":[` + entry + `]} {}`,
		"duplicate key": `{"Modules":[` + entry + `,` + entry + `]}`,
		"wrong type":    `{"Modules":{"Key":"m"}}`,
		"too large":     `{"Modules":[` + entry + `],"Pad":"` + strings.Repeat("x", 1<<20) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := files(t, map[string]string{
				"main.tf":                      module("m", "acme/m/aws"),
				".terraform/modules/m/main.tf": "",
				manifestPath:                   manifest,
			})
			tree := loadTrusted(t, dir, ".")
			if diff := cmp.Diff([]string{"module.m !remote_source"}, flatten(tree.Root)); diff != "" {
				t.Errorf("tree (-want +got):\n%s", diff)
			}
			if got := moduleDiags(tree, terraform.DiagModuleManifestInvalid); len(got) != 1 {
				t.Errorf("module_manifest_invalid = %v, want one warning", got)
			}
		})
	}
}

// The manifest belongs to the root module's directory, and its Dirs are relative to it.
func TestManifestOfANestedRoot(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"envs/prod/main.tf":                      module("m", "acme/m/aws"),
		"envs/prod/.terraform/modules/m/main.tf": `resource "aws_vpc" "v" {}`,
		"envs/prod/" + manifestPath:              `{"Modules":[{"Key":"m","Source":"registry.terraform.io/acme/m/aws","Dir":".terraform/modules/m"}]}`,
	})
	tree := loadTrusted(t, dir, "envs/prod")
	if diff := cmp.Diff([]string{"module.m envs/prod/.terraform/modules/m"}, flatten(tree.Root)); diff != "" {
		t.Errorf("tree (-want +got):\n%s", diff)
	}
	if !slices.ContainsFunc(tree.Root.Calls[0].Child.Module.Blocks, func(b terraform.Block) bool { return b.Type == "resource" }) {
		t.Error("the resolved remote module was not parsed")
	}
}

// The manifest is untrusted repository content unless the pipeline says otherwise: without
// TrustModuleManifest it is never read, and remote calls stay unresolved.
func TestManifestIsIgnoredUnlessTrusted(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":                      module("m", "acme/m/aws"),
		".terraform/modules/m/main.tf": "",
		manifestPath:                   `{"Modules":[{"Key":"m","Source":"registry.terraform.io/acme/m/aws","Dir":".terraform/modules/m"}]}`,
	})
	tree := loadTree(t, dir, ".")
	if diff := cmp.Diff([]string{"module.m !remote_source"}, flatten(tree.Root)); diff != "" {
		t.Errorf("tree (-want +got):\n%s", diff)
	}
	invalid := files(t, map[string]string{"main.tf": module("m", "acme/m/aws"), manifestPath: "{"})
	if got := moduleDiags(loadTree(t, invalid, "."), terraform.DiagModuleManifestInvalid); len(got) != 0 {
		t.Errorf("an untrusted manifest was read: %v", got)
	}
}

// The manifest holds at most 10,000 entries.
func TestManifestEntryLimit(t *testing.T) {
	t.Parallel()
	for n, usable := range map[int]bool{9_999: true, 10_000: true, 10_001: false} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			b.WriteString(`{"Modules":[{"Key":"m","Source":"registry.terraform.io/acme/m/aws","Dir":".terraform/modules/m"}`)
			for i := 1; i < n; i++ {
				fmt.Fprintf(&b, `,{"Key":"k%d"}`, i)
			}
			b.WriteString("]}")
			dir := files(t, map[string]string{
				"main.tf":                      module("m", "acme/m/aws"),
				".terraform/modules/m/main.tf": "",
				manifestPath:                   b.String(),
			})
			tree := loadTrusted(t, dir, ".")
			resolved := tree.Root.Calls[0].Child != nil
			if resolved != usable {
				t.Errorf("%d entries: resolved %v, want %v", n, resolved, usable)
			}
		})
	}
}
