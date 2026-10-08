package terraform

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// fileModule writes files under a scan root and parses the module in "mod" with one main.tf
// holding `locals { v = expr }`. Paths ending in "/" are directories.
func fileModule(t *testing.T, files map[string]string, expr string) (*ParsedModule, string) {
	t.Helper()
	dir := t.TempDir()
	files["mod/main.tf"] = "locals {\n  v = " + expr + "\n}\n"
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if strings.HasSuffix(name, "/") {
			if err := os.MkdirAll(p, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	m, err := ParseModule(context.Background(), r, Dir{Path: "mod", Files: []string{"mod/main.tf"}}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return m, dir
}

// evalFileLocal evaluates local.v in a fileModule with vars.
func evalFileLocal(t *testing.T, files map[string]string, expr string, vars map[string]Variable) (*ParsedModule, cty.Value) {
	t.Helper()
	m, _ := fileModule(t, files, expr)
	locals, err := m.EvaluateLocals(context.Background(), vars)
	if err != nil {
		t.Fatal(err)
	}
	return m, locals["v"].Value
}

func diagSummary(m *ParsedModule) []string {
	var out []string
	for _, d := range m.Diagnostics {
		out = append(out, string(d.Code)+"@"+d.File)
	}
	return out
}

// testFiles is a scan root with a module in mod and a secret beside it.
func testFiles() map[string]string {
	return map[string]string{
		"secret.txt":        "outside the module",
		"mod/data.json":     `{"a": 1}`,
		"mod/sub/note.txt":  "nested",
		"mod/dir/":          "",
		"mod/bin.dat":       "\xff\xfe",
		"mod/t.tftpl":       "Hello ${upper(name)}!%{ for i in items } [${i}]%{ endfor }",
		"mod/missing.tftpl": "${nosuch}",
		"mod/foreign.tftpl": "${var.x}",
		"mod/nested.tftpl":  `${templatefile("t.tftpl", {})}`,
		"mod/uuid.tftpl":    "id-${uuid()}",
		"mod/number.tftpl":  "${n}",
		"mod/bad.tftpl":     "${",
		"mod/complex.tftpl": "${" + strings.Repeat("1+", maxOperators+1) + "1}",
	}
}

func TestFileFunctions(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		expr  string
		want  string // an HCL literal, or "unknown"
		diags []string
	}{
		{`file("data.json")`, `"{\"a\": 1}"`, nil},
		{`file("./sub/note.txt")`, `"nested"`, nil},
		{`file("${path.module}/data.json")`, `"{\"a\": 1}"`, nil},
		{`jsondecode(file("data.json")).a`, `1`, nil},
		{`file("sub/../data.json")`, `"{\"a\": 1}"`, nil},
		{`file("missing.txt")`, `unknown`, []string{"file_unreadable@mod/main.tf"}},
		{`file("../secret.txt")`, `unknown`, []string{"file_outside_module@mod/main.tf"}},
		{`file("sub/../../secret.txt")`, `unknown`, []string{"file_outside_module@mod/main.tf"}},
		{`file("/etc/hostname")`, `unknown`, []string{"file_outside_module@mod/main.tf"}},
		{`file("~/.ssh/id_rsa")`, `unknown`, []string{"file_outside_module@mod/main.tf"}},
		{`file("C:/Windows/win.ini")`, `unknown`, []string{"file_outside_module@mod/main.tf"}},
		{`file("")`, `unknown`, []string{"file_outside_module@mod/main.tf"}},
		{`file("dir")`, `unknown`, []string{"file_unreadable@mod/main.tf"}},
		{`file("bin.dat")`, `unknown`, []string{"file_unreadable@mod/main.tf"}},
		{`{ a = file("missing.txt"), b = "kept" }`, `unknown`, []string{"file_unreadable@mod/main.tf"}},

		{`fileexists("data.json")`, `true`, nil},
		{`fileexists("nope.txt")`, `false`, nil},
		{`fileexists("${path.module}/sub/note.txt")`, `true`, nil},
		{`fileexists("../secret.txt")`, `unknown`, []string{"file_outside_module@mod/main.tf"}},
		{`fileexists("dir")`, `unknown`, []string{"file_unreadable@mod/main.tf"}},

		{`templatefile("t.tftpl", { name = "x", items = ["a", "b"] })`, `"Hello X! [a] [b]"`, nil},
		{`templatefile("number.tftpl", { n = 5 })`, `"5"`, nil},
		{`templatefile("t.tftpl", { name = "x" })`, `unknown`, []string{"template_error@mod/t.tftpl"}},
		{`templatefile("missing.tftpl", {})`, `unknown`, []string{"template_error@mod/missing.tftpl"}},
		{`templatefile("foreign.tftpl", {})`, `unknown`, []string{"template_error@mod/foreign.tftpl"}},
		{`templatefile("nested.tftpl", {})`, `unknown`, []string{"template_error@mod/nested.tftpl"}},
		{`templatefile("bad.tftpl", {})`, `unknown`, []string{"template_error@mod/bad.tftpl"}},
		{`templatefile("complex.tftpl", {})`, `unknown`, []string{"expression_too_complex@mod/complex.tftpl"}},
		{`templatefile("uuid.tftpl", {})`, `unknown`, []string{"unsupported_function@mod/uuid.tftpl"}},
		{`templatefile("../secret.txt", {})`, `unknown`, []string{"file_outside_module@mod/main.tf"}},
		{`templatefile("t.tftpl", { "not an identifier" = 1 })`, `unknown`, []string{"evaluation@mod/main.tf"}},
		{`templatefile("t.tftpl", "x")`, `unknown`, []string{"evaluation@mod/main.tf"}},
	} {
		m, got := evalFileLocal(t, testFiles(), c.expr, nil)
		if diff := cmp.Diff(c.diags, diagSummary(m)); diff != "" {
			t.Errorf("%s: diagnostics (-want +got):\n%s", c.expr, diff)
		}
		if c.want == "unknown" {
			if got.IsWhollyKnown() {
				t.Errorf("%s = %#v, want unknown", c.expr, got)
			}
			continue
		}
		if want := literal(t, c.want); !got.IsKnown() || !got.Equals(want).True() {
			t.Errorf("%s = %#v, want %s", c.expr, got, c.want)
		}
	}
}

func TestFileFunctionsUnknownAndSensitive(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"u": {Value: cty.UnknownVal(cty.String)},
		"s": {Value: cty.StringVal("data.json").Mark(SensitiveMark)},
		"n": {Value: cty.StringVal("x").Mark(SensitiveMark)},
		"o": {Value: cty.UnknownVal(cty.Map(cty.String))},
	}
	for _, c := range []struct {
		expr      string
		known     bool
		sensitive bool
	}{
		{`file(var.u)`, false, false},
		{`fileexists(var.u)`, false, false},
		{`templatefile(var.u, {})`, false, false},
		{`templatefile("t.tftpl", var.o)`, false, false},
		{`templatefile("t.tftpl", { name = var.u, items = [] })`, false, false},
		{`file(var.s)`, true, true},
		{`fileexists(var.s)`, true, true},
		{`templatefile("t.tftpl", { name = var.n, items = [] })`, true, true},
	} {
		m, got := evalFileLocal(t, testFiles(), c.expr, vars)
		if got.IsWhollyKnown() != c.known || got.HasMark(SensitiveMark) != c.sensitive || len(m.Diagnostics) != 0 {
			t.Errorf("%s = %#v, diagnostics %v; want known %v, sensitive %v", c.expr, got, m.Diagnostics, c.known, c.sensitive)
		}
	}
}

// TestFileSizeLimits: files are read up to maxFunctionFileSize; the result is then bounded like
// any function result, and the bytes read count toward the module's function work.
func TestFileSizeLimits(t *testing.T) {
	t.Parallel()
	files := testFiles()
	files["mod/fits.txt"] = strings.Repeat("x", maxFunctionValueSize-1) // a string of size 2^18
	files["mod/over.txt"] = strings.Repeat("x", maxFunctionValueSize)
	files["mod/max.txt"] = strings.Repeat("x", maxFunctionFileSize)
	files["mod/big.txt"] = strings.Repeat("x", maxFunctionFileSize+1)
	for name, want := range map[string][]DiagCode{
		"fits.txt": nil,
		"over.txt": {DiagFunctionLimit},
		"max.txt":  {DiagFunctionLimit},
		"big.txt":  {DiagFileUnreadable},
	} {
		m, got := evalFileLocal(t, maps.Clone(files), `length(file("`+name+`"))`, nil)
		if diff := cmp.Diff(want, diagCodes(m)); diff != "" {
			t.Errorf("%s: diagnostics (-want +got):\n%s", name, diff)
		}
		if got.IsKnown() != (want == nil) {
			t.Errorf("%s: length = %#v", name, got)
		}
	}

	// file("data.json") costs 10 for its argument, fileCallCost before touching the
	// filesystem, 8 for the bytes read and 9 for its result. fileexists("data.json") costs 10,
	// fileCallCost and 1. A read of fits.txt with less work left than its size is refused by
	// size, before reading.
	const file, exists = 10 + fileCallCost + 8 + 9, 10 + fileCallCost + 1
	for _, c := range []struct {
		expr      string
		remaining int
		limited   bool
	}{
		{`file("data.json")`, file + 1, false},
		{`file("data.json")`, file, false},
		{`file("data.json")`, file - 1, true},
		{`file("data.json")`, 10 + fileCallCost - 1, true},
		{`fileexists("data.json")`, exists, false},
		{`fileexists("data.json")`, exists - 1, true},
		{`length(file("fits.txt"))`, 18 + fileCallCost + maxFunctionValueSize, true},
	} {
		files := testFiles()
		files["mod/fits.txt"] = strings.Repeat("x", maxFunctionValueSize-1)
		m, _ := fileModule(t, files, c.expr)
		m.fnWork = maxFunctionWork - c.remaining
		locals, err := m.EvaluateLocals(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		limited := slices.Equal(diagCodes(m), []DiagCode{DiagFunctionLimit})
		if limited != c.limited || locals["v"].Value.IsKnown() == c.limited {
			t.Errorf("%s with %d work left = %#v, diagnostics %v; want limited %v", c.expr, c.remaining, locals["v"].Value, m.Diagnostics, c.limited)
		}
	}
}

// TestFileFunctionsWithoutRoot: a module built without a scan root reads nothing.
func TestFileFunctionsWithoutRoot(t *testing.T) {
	t.Parallel()
	m := &ParsedModule{Dir: "."}
	got, err := m.functions(nil, nil)["file"].Call([]cty.Value{cty.StringVal("main.tf")})
	if err != nil || got.IsKnown() || len(m.fnDiags) != 1 || m.fnDiags[0].code != DiagFileUnreadable {
		t.Errorf("file without a root = %#v, %v, pending %v", got, err, m.fnDiags)
	}
}

// TestEveryReadIsCharged: bytes read are charged even when the file is then refused (not
// UTF-8 here), so a loop over such a file stops reading once the work is spent.
func TestEveryReadIsCharged(t *testing.T) {
	t.Parallel()
	files := testFiles()
	files["mod/bad.bin"] = strings.Repeat("\xff", maxFunctionFileSize)
	m, _ := fileModule(t, files, `[for i in range(100) : [for j in range(100) : length(file("bad.bin"))]]`)
	locals, err := m.EvaluateLocals(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if locals["v"].Value.IsWhollyKnown() || m.fileBytesRead > m.fnWork || m.fnWork > maxFunctionWork {
		t.Errorf("bytes read %d, work %d: every byte read must be charged", m.fileBytesRead, m.fnWork)
	}
	if !slices.Contains(diagCodes(m), DiagFileUnreadable) || !slices.Contains(diagCodes(m), DiagFunctionLimit) {
		t.Errorf("diagnostics %v, want file_unreadable and function_limit", m.Diagnostics)
	}
}

// TestFileReadsStopWhenTheBudgetIsSpent: once less work is left than a file's size, calls are
// refused by size without reading, and each still pays fileCallCost, so a loop of reads cannot
// keep reading.
func TestFileReadsStopWhenTheBudgetIsSpent(t *testing.T) {
	t.Parallel()
	files := testFiles()
	files["mod/big.txt"] = strings.Repeat("x", maxFunctionFileSize)
	m, _ := fileModule(t, files, `[for i in range(1000) : length(file("big.txt"))]`)
	m.fnWork = maxFunctionWork - maxFunctionFileSize/2
	locals, err := m.EvaluateLocals(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if locals["v"].Value.IsWhollyKnown() || !slices.Contains(diagCodes(m), DiagFunctionLimit) {
		t.Errorf("reads past the budget = %#v, diagnostics %v", locals["v"].Value, m.Diagnostics)
	}
	// The remaining half MiB covers at most 512 calls' fileCallCost, and no read happened.
	if m.fnWork > maxFunctionWork || m.fnWork < maxFunctionWork-fileCallCost || m.fileBytesRead != 0 {
		t.Errorf("work after the loop = %d, bytes read %d; want the budget spent by per-call charges and nothing read", m.fnWork, m.fileBytesRead)
	}
}
