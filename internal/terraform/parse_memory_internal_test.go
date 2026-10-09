package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// Ceilings on the live heap that lexing (the nesting guard) and parsing one file at the size
// limit may hold, diagnostics included (ADR 0016). Measured at 1 MiB, the worst shapes hold 286 MB
// of tokens and diagnostics (an error flood) and 168 MB of syntax tree and diagnostics.
const (
	lexMemoryCeiling   = 320 << 20
	parseMemoryCeiling = 192 << 20
)

var memorySink any

// liveHeap returns the live heap after two collections.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// fill repeats line, formatted with a counter, up to n bytes.
func fill(n int, line string) string {
	var b strings.Builder
	for i := 0; b.Len()+len(line)+8 < n; i++ {
		fmt.Fprintf(&b, line, i)
	}
	return b.String()
}

// TestParseMemoryPerFile: the guard's tokens and the parse of a worst-case file at the size limit
// stay under parseMemoryCeiling, so one file fits the 1 GiB scan budget (ADR 0016).
func TestParseMemoryPerFile(t *testing.T) {
	limit := int(DefaultLimits().MaxFileSize)
	shapes := map[string]string{
		"dense attributes":     fill(limit, "a%d=1\n"),
		"duplicate attributes": strings.Repeat("a=1\n", limit/4-1),
		"long list":            "a = [" + strings.Repeat("1,", limit/2-8) + "]\n",
		"error flood":          strings.Repeat("@", limit-1),
		"operator chain":       "a = 1" + strings.Repeat("+1", limit/2-8) + "\n",
		"unary chain":          "a = 1" + strings.Repeat("+-1", limit/3-8) + "\n",
		"empty blocks":         strings.Repeat("b{}\n", limit/4-1),
		"negations":            "a = [" + strings.Repeat("!x,", limit/3-8) + "]\n",
		"json list":            `{"locals":{"a":[` + strings.Repeat("1,", limit/2-32) + `1]}}`,
	}
	for name, src := range shapes {
		data := []byte(src)
		file := "x.tf"
		if strings.HasPrefix(name, "json") {
			file = "x.tf.json"
		}
		// The parse's diagnostics are held with its result: an error flood keeps one per byte.
		var lexed int64
		if file == "x.tf" {
			base := liveHeap()
			tokens, diags := hclsyntax.LexConfig(data, file, hcl.InitialPos)
			memorySink = [2]any{tokens, diags}
			lexed = max(int64(liveHeap())-int64(base), 0)
			memorySink = nil
		}
		base := liveHeap()
		if file == "x.tf" {
			f, diags := hclsyntax.ParseConfig(data, file, hcl.InitialPos)
			memorySink = [2]any{f, diags}
		} else {
			f, diags := hcljson.Parse(data, file)
			memorySink = [2]any{f, diags}
		}
		parsed := max(int64(liveHeap())-int64(base), 0)
		memorySink = nil
		t.Logf("%s (%d bytes): lexer tokens %d MB, syntax tree %d MB", name, len(data), lexed>>20, parsed>>20)
		if lexed > lexMemoryCeiling || parsed > parseMemoryCeiling {
			t.Errorf("%s: lexer %d MB, parse %d MB; want under %d and %d MB",
				name, lexed>>20, parsed>>20, lexMemoryCeiling>>20, parseMemoryCeiling>>20)
		}
	}
}

// hclDiags returns n hcl diagnostics of severity sev.
func hclDiags(n int, sev hcl.DiagnosticSeverity) hcl.Diagnostics {
	out := make(hcl.Diagnostics, n)
	for i := range out {
		out[i] = &hcl.Diagnostic{
			Severity: sev, Summary: fmt.Sprintf("problem %d", i),
			Subject: &hcl.Range{Filename: "x.tf", Start: hcl.Pos{Line: i + 1, Column: 1}},
		}
	}
	return out
}

// A file keeps at most maxDiagnosticsPerFile hcl diagnostics, then one too_many_diagnostics that
// is an error once any dropped diagnostic is, across calls; other files count on their own.
func TestHCLDiagnosticsAreCappedPerFile(t *testing.T) {
	t.Parallel()
	count := func(m *ParsedModule, code DiagCode) int {
		n := 0
		for _, d := range m.Diagnostics {
			if d.Code == code {
				n++
			}
		}
		return n
	}
	for _, n := range []int{maxDiagnosticsPerFile - 1, maxDiagnosticsPerFile} {
		m := &ParsedModule{}
		m.addParseDiags("x.tf", hclDiags(n, hcl.DiagWarning))
		if count(m, DiagSyntax) != n || count(m, DiagTooManyDiagnostics) != 0 {
			t.Errorf("%d diagnostics: kept %d, too_many %d", n, count(m, DiagSyntax), count(m, DiagTooManyDiagnostics))
		}
	}
	m := &ParsedModule{}
	m.addParseDiags("x.tf", hclDiags(maxDiagnosticsPerFile+1, hcl.DiagWarning))
	if count(m, DiagSyntax) != maxDiagnosticsPerFile || count(m, DiagTooManyDiagnostics) != 1 || m.HasErrors() {
		t.Errorf("101 warnings: kept %d, too_many %d, errors %v", count(m, DiagSyntax), count(m, DiagTooManyDiagnostics), m.HasErrors())
	}
	m.sortDiagnostics()
	m.addParseDiags("x.tf", hclDiags(1000, hcl.DiagError)) // a second call for the same file
	m.addParseDiags("y.tf", hclDiags(3, hcl.DiagWarning))
	if count(m, DiagSyntax) != maxDiagnosticsPerFile+3 || count(m, DiagTooManyDiagnostics) != 1 || !m.HasErrors() {
		t.Errorf("then 1000 errors: kept %d, too_many %d, errors %v", count(m, DiagSyntax), count(m, DiagTooManyDiagnostics), m.HasErrors())
	}
}

// Every diagnostic parsing adds counts toward the per-file cap: invalid characters (hcl's),
// unsupported blocks and top-level arguments (iace's) each stay at about a hundred.
func TestParseModuleCapsDiagnosticFloods(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		src    string
		errors bool
	}{
		"invalid characters":  {strings.Repeat("@", 1<<20-1), true},
		"unsupported blocks":  {strings.Repeat("b{}\n", 1<<18-1), false},
		"top-level arguments": {fill(1<<20, "a%d=1\n"), true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := parseLocalsModule(t, tc.src)
			n := 0
			for _, d := range m.Diagnostics {
				if d.Code == DiagTooManyDiagnostics {
					n++
				}
			}
			if len(m.Diagnostics) > maxDiagnosticsPerFile+1 || n != 1 || m.HasErrors() != tc.errors {
				t.Errorf("%d diagnostics, %d too_many, errors %v", len(m.Diagnostics), n, m.HasErrors())
			}
		})
	}
}

// Evaluation diagnostics are not counted: they are bounded by the expressions, and repeated
// evaluations of one expression must not trigger the cap.
func TestEvaluationDiagnosticsAreNotCapped(t *testing.T) {
	t.Parallel()
	m := &ParsedModule{}
	m.addHCLDiags("x.tf", hclDiags(maxDiagnosticsPerFile+50, hcl.DiagError))
	for _, d := range m.Diagnostics {
		if d.Code == DiagTooManyDiagnostics {
			t.Fatal("evaluation diagnostics triggered the parse cap")
		}
	}
	if len(m.Diagnostics) != maxDiagnosticsPerFile+50 {
		t.Errorf("%d diagnostics kept", len(m.Diagnostics))
	}
}

// tfvars files are untrusted input with the same per-file cap: an error flood or a flood of
// undeclared variables keeps about a hundred diagnostics.
func TestTfvarsDiagnosticFloodsAreCapped(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		tfvars string
		errors bool
	}{
		"invalid characters":   {strings.Repeat("@", 1<<20-1), true},
		"undeclared variables": {fill(1<<20, "a%d=1\n"), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for file, src := range map[string]string{"main.tf": `variable "x" {}`, "terraform.tfvars": tc.tfvars} {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(src), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r, err := fsutil.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })
			m, err := ParseModule(context.Background(), r, Dir{Path: ".", Files: []string{"main.tf"}}, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.EvaluateVariables(context.Background(), r, VarOptions{}, DefaultLimits()); err != nil {
				t.Fatal(err)
			}
			kept, tooMany := 0, 0
			for _, d := range m.Diagnostics {
				if d.File == "terraform.tfvars" {
					kept++
				}
				if d.Code == DiagTooManyDiagnostics {
					tooMany++
				}
			}
			if kept > maxDiagnosticsPerFile+1 || tooMany != 1 || m.HasErrors() != tc.errors {
				t.Errorf("%d diagnostics for the tfvars, %d too_many, errors %v", kept, tooMany, m.HasErrors())
			}
		})
	}
}
