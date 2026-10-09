//go:build unix

package terraform_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// Symlinked module directories are never followed, as discovery never follows symlinked
// directories: a link to an ancestor would otherwise defeat cycle detection by path.
func TestLoadModuleTreeSymlinks(t *testing.T) {
	t.Parallel()
	outside := files(t, map[string]string{"mod/main.tf": `resource "aws_vpc" "v" {}`})
	dir := files(t, map[string]string{
		"main.tf": module("out", "./out") + module("alias", "./alias") + module("abs", "./abs") +
			module("a", "./a") + module("through", "./alias/sub"),
		"a/main.tf":        module("s", "./self"),
		"real/sub/main.tf": `resource "aws_vpc" "v" {}`,
	})
	for name, target := range map[string]string{
		"out":    filepath.Join("..", filepath.Base(outside), "mod"),
		"abs":    filepath.Join(outside, "mod"),
		"alias":  "real",
		"a/self": ".",
	} {
		if err := os.Symlink(target, filepath.Join(dir, filepath.FromSlash(name))); err != nil {
			t.Fatal(err)
		}
	}
	tree := loadTree(t, dir, ".")
	want := []string{
		"module.out !symlinked_directory",
		"module.alias !symlinked_directory",
		"module.abs !symlinked_directory",
		"module.a a",
		"module.a.module.s !symlinked_directory",
		"module.through !symlinked_directory",
	}
	if diff := cmp.Diff(want, flatten(tree.Root)); diff != "" {
		t.Errorf("tree (-want +got):\n%s", diff)
	}
}

func TestLoadModuleTreeRecordsSkipsInUndiscoveredDirs(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{
		"main.tf":            module("x", "./.modules/x"),
		".modules/x/main.tf": `resource "aws_vpc" "v" {}`,
	})
	if err := os.Symlink("missing.tf", filepath.Join(dir, ".modules", "x", "dangling.tf")); err != nil {
		t.Fatal(err)
	}
	tree := loadTree(t, dir, ".")
	if len(tree.Skipped) != 1 || tree.Skipped[0].Path != ".modules/x/dangling.tf" ||
		tree.Skipped[0].Reason != terraform.SkipSymlinkEscape {
		t.Errorf("Skipped = %v, want the dangling symlink", tree.Skipped)
	}
	if got := flatten(tree.Root); len(got) != 1 || got[0] != "module.x .modules/x" {
		t.Errorf("tree = %v", got)
	}
}
