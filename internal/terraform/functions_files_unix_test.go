//go:build unix

package terraform

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// TestFileFunctionsRefuseSymlinkEscapes: a symlink that leaves the scan root is refused; one
// whose target is inside the scan root, in the module directory or not, is followed (ADR 0015).
func TestFileFunctionsRefuseSymlinkEscapes(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		expr  string
		want  cty.Value
		diags []DiagCode
	}{
		{`file("up.txt")`, cty.StringVal("outside the module"), nil},
		{`file("abs.txt")`, cty.DynamicVal, []DiagCode{DiagFileUnreadable}},
		{`file("escape.txt")`, cty.DynamicVal, []DiagCode{DiagFileUnreadable}},
		{`fileexists("escape.txt")`, cty.DynamicVal, []DiagCode{DiagFileUnreadable}},
		{`templatefile("escape.txt", {})`, cty.DynamicVal, []DiagCode{DiagFileUnreadable}},
		{`file("inside.txt")`, cty.StringVal("nested"), nil},
		{`file("linkdir/note.txt")`, cty.StringVal("nested"), nil},
		{`file("outdir/x.txt")`, cty.DynamicVal, []DiagCode{DiagFileUnreadable}},
	} {
		m, dir := fileModule(t, testFiles(), c.expr)
		if err := os.MkdirAll(filepath.Join(dir, "other"), 0o700); err != nil {
			t.Fatal(err)
		}
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("not in the scan root"), 0o600); err != nil {
			t.Fatal(err)
		}
		for name, target := range map[string]string{
			"up.txt":     filepath.Join("..", "secret.txt"),
			"abs.txt":    filepath.Join(dir, "secret.txt"),
			"inside.txt": filepath.Join("sub", "note.txt"),
			"linkdir":    "sub",
			"outdir":     filepath.Join("..", "other"),
			"escape.txt": filepath.Join("..", "..", filepath.Base(outside), "secret.txt"),
		} {
			if err := os.Symlink(target, filepath.Join(dir, "mod", name)); err != nil {
				t.Fatal(err)
			}
		}
		locals, err := m.EvaluateLocals(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		got := locals["v"].Value
		if c.want.IsKnown() && !got.RawEquals(c.want) || !c.want.IsKnown() && got.IsKnown() {
			t.Errorf("%s = %#v, want %#v", c.expr, got, c.want)
		}
		if !slices.Equal(diagCodes(m), c.diags) {
			t.Errorf("%s: diagnostics %v, want %v", c.expr, m.Diagnostics, c.diags)
		}
	}
}
