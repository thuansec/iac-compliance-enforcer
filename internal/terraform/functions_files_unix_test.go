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

// TestFileFunctionsRefuseSymlinkEscapes: a symlink in the module that leaves the module
// directory is refused, even when its target is inside the scan root; one that stays inside is
// followed.
func TestFileFunctionsRefuseSymlinkEscapes(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		expr  string
		want  cty.Value
		diags []DiagCode
	}{
		{`file("up.txt")`, cty.DynamicVal, []DiagCode{DiagFileUnreadable}},
		{`file("abs.txt")`, cty.DynamicVal, []DiagCode{DiagFileUnreadable}},
		{`fileexists("up.txt")`, cty.DynamicVal, []DiagCode{DiagFileUnreadable}},
		{`templatefile("up.txt", {})`, cty.DynamicVal, []DiagCode{DiagFileUnreadable}},
		{`file("inside.txt")`, cty.StringVal("nested"), nil},
		{`file("linkdir/note.txt")`, cty.StringVal("nested"), nil},
		{`file("outdir/x.txt")`, cty.DynamicVal, []DiagCode{DiagFileUnreadable}},
	} {
		m, dir := fileModule(t, testFiles(), c.expr)
		if err := os.MkdirAll(filepath.Join(dir, "other"), 0o700); err != nil {
			t.Fatal(err)
		}
		for name, target := range map[string]string{
			"up.txt":     filepath.Join("..", "secret.txt"),
			"abs.txt":    filepath.Join(dir, "secret.txt"),
			"inside.txt": filepath.Join("sub", "note.txt"),
			"linkdir":    "sub",
			"outdir":     filepath.Join("..", "other"),
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
