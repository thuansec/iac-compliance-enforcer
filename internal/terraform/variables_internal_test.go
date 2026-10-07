package terraform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// TestVarFileNamingAModuleFileKeepsItsSource: a --var-file may name one of the module's own
// files; evaluating it as tfvars must not drop the source that later evaluation needs.
func TestVarFileNamingAModuleFileKeepsItsSource(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `{"variable": {"v": {"default": "x"}}}`
	if err := os.WriteFile(filepath.Join(dir, "main.tf.json"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	limits := DefaultLimits()
	m, err := ParseModule(context.Background(), r, Dir{Path: ".", Files: []string{"main.tf.json"}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.EvaluateVariables(context.Background(), r, VarOptions{VarFiles: []string{"main.tf.json"}}, limits); err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}
	attrs, _ := m.Blocks[0].Body.JustAttributes()
	if !m.safeToEvaluate(attrs["default"].Expr) {
		t.Error("the module file's source was dropped: its expressions can no longer be evaluated")
	}
}
