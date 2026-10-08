package terraform

import (
	"context"
	"regexp"
	"regexp/syntax"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

func TestRegexFunctions(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		expr string
		want string // an HCL literal, or "error"
	}{
		{`replace("a-b-c", "-", "_")`, `"a_b_c"`},
		{`replace("hello", "", "-")`, `"-h-e-l-l-o-"`},
		{`replace("été", "", ".")`, `".é.t.é."`},
		{`replace("abc", "x", "y")`, `"abc"`},
		{`replace("a/b", "/", "-")`, `"a-b"`},
		{`replace("a1b22", "/\\d+/", "#")`, `"a#b#"`},
		{`replace("abc", "/(b)/", "[$1$1]")`, `"a[bb]c"`},
		{`replace("k=v", "/(?P<key>\\w)=(?P<val>\\w)/", "$val=$key")`, `"v=k"`},
		{`replace("abc", "//", "-")`, `"-a-b-c-"`},
		{`replace("abc", "/(/", "-")`, `error`},

		{`regex("\\d+", "a12b")`, `"12"`},
		{`regex("^(\\w+):(\\w+)", "arn:aws:s3")`, `["arn", "aws"]`},
		{`regex("(?P<k>\\w)=(?P<v>\\w)", "a=b")`, `{ k = "a", v = "b" }`},
		{`regex("z", "abc")`, `error`},
		{`regex("(", "abc")`, `error`},

		{`regexall("\\d", "a1b2")`, `["1", "2"]`},
		{`regexall("(\\w)=(\\w)", "a=b c=d")`, `[["a", "b"], ["c", "d"]]`},
		{`length(regexall("z", "abc"))`, `0`},
	} {
		m, got := evalLocal(t, c.expr, nil)
		if c.want == "error" {
			if got.IsKnown() || !slices.Equal(diagCodes(m), []DiagCode{DiagEvaluation}) {
				t.Errorf("%s = %#v, diagnostics %v; want unknown with an evaluation warning", c.expr, got, m.Diagnostics)
			}
			continue
		}
		want, err := convert.Convert(literal(t, c.want), got.Type())
		if err != nil || len(m.Diagnostics) != 0 || !got.IsKnown() || !got.Equals(want).True() {
			t.Errorf("%s = %#v, diagnostics %v; want %s", c.expr, got, m.Diagnostics, c.want)
		}
	}
}

func TestRegexUnknownAndSensitive(t *testing.T) {
	t.Parallel()
	vars := map[string]Variable{
		"u": {Value: cty.UnknownVal(cty.String)},
		"s": {Value: cty.StringVal("secret-1").Mark(SensitiveMark)},
	}
	for _, expr := range []string{`replace(var.u, "a", "b")`, `regex(var.u, "a")`, `regexall("a", var.u)`} {
		if _, got := evalLocal(t, expr, vars); got.IsKnown() {
			t.Errorf("%s = %#v, want unknown", expr, got)
		}
	}
	for _, expr := range []string{`replace(var.s, "-", "_")`, `replace(var.s, "/\\d/", "#")`, `regex("\\d", var.s)`, `regexall("\\w", var.s)`} {
		if _, got := evalLocal(t, expr, vars); !got.HasMark(SensitiveMark) {
			t.Errorf("%s = %#v, want sensitive", expr, got)
		}
	}
}

// TestRegexSizeNeverUnderestimates: the parse-tree estimate is at least the program Go
// compiles, so a pattern the estimate admits compiles to at most twice the program limit.
func TestRegexSizeNeverUnderestimates(t *testing.T) {
	t.Parallel()
	for _, pattern := range []string{
		`a`, `abc`, `ab|cd`, `(a)`, `a*`, `[a-z]+`, `a?`, `a{3}`, `a{2,5}`, `a{2,}`, `a{0,1000}`,
		`(?:ab){10}`, `(?:a*b*)*`, `(?i)abc`, `\pL+\d*`, `^a$`, `\bx\B`, `(?s).`, `(?U)a+?`,
		`(?:a{0,30}b){0,30}`, `a{0,999}b{0,999}c{0,999}d{0,999}`, `(x?){1000}`, `((a|b)*c)+`,
		`(?P<k>\w+)=(?P<v>[^,]*)`, `x*y|x`, `(?:(?:a|b|c){2,7}){3}`,
	} {
		parsed, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("parse %q: %v", pattern, err)
		}
		prog, err := syntax.Compile(parsed.Simplify())
		if err != nil {
			t.Fatalf("compile %q: %v", pattern, err)
		}
		if est := regexSize(parsed); est < len(prog.Inst) && est <= 2*maxRegexProgram {
			t.Errorf("regexSize(%q) = %d, below the %d instructions Go compiles", pattern, est, len(prog.Inst))
		}
	}
}

// TestRegexRefusedBeforeWork: an over-long pattern is never parsed (nor charged as parsed), a
// pattern whose estimate is far over the program limit is never compiled, one just over it is
// compiled but not used, and parsing is charged once per pattern.
func TestRegexRefusedBeforeWork(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("[a-z]{1000}", 3000)
	big := strings.Repeat(`[a-z]{1000}`, 5)          // Go rejects nested counts past 1,000 itself
	justOver := strings.Repeat("a", maxRegexProgram) // compiles to maxRegexProgram + 2
	fits := strings.Repeat("a", maxRegexProgram-2)
	for _, c := range []struct {
		pattern          string
		charged, limited bool
	}{
		{long, false, true},
		{big, true, true},
		{justOver, true, true},
		{fits, true, false},
	} {
		m := &ParsedModule{}
		_, limited := boundedCall(t, m, "regexall", cty.StringVal(c.pattern), cty.StringVal("x"))
		e := m.regexes[c.pattern]
		charged := m.fnWork >= regexParseCost*len(c.pattern)
		if limited != c.limited || charged != c.charged || (e.re != nil) == c.limited {
			t.Errorf("regexall(%.20q…): limited %v, parse charged %v, compiled %v", c.pattern, limited, charged, e.re != nil)
		}
	}
	// The same pattern is parsed and charged once.
	m := &ParsedModule{}
	boundedCall(t, m, "regex", cty.StringVal("a+"), cty.StringVal("aa"))
	first := m.fnWork
	boundedCall(t, m, "regex", cty.StringVal("a+"), cty.StringVal("aa"))
	if second := m.fnWork - first; second >= first {
		t.Errorf("second call charged %d, the first %d: the parse was charged again", second, first)
	}
}

// TestRegexSearchesAreCharged: finding all matches searches once per match, and each search
// can scan the rest of the input, so `x*y|x` over n "x" is quadratic. The charge per search
// stops it.
func TestRegexSearchesAreCharged(t *testing.T) {
	t.Parallel()
	s := cty.StringVal(strings.Repeat("x", 40000))
	for _, args := range [][]cty.Value{
		{cty.StringVal("x*y|x"), s},
		{s, cty.StringVal("/x*y|x/"), cty.StringVal("")},
	} {
		name := "regexall"
		if len(args) == 3 {
			name = "replace"
		}
		m := &ParsedModule{}
		if _, limited := boundedCall(t, m, name, args...); !limited || m.fnWork > maxFunctionWork {
			t.Errorf("%s over 40,000 bytes with x*y|x: limited %v, work %d", name, limited, m.fnWork)
		}
	}

	// regexall("ab", n "x") searches once: it needs 3 searches' work to be affordable (2k+1 for
	// one match more than it found), after its arguments (3, n+1) and the parse (3 × 64, plus
	// its 2 literal runes).
	const n = 1000
	probe := &ParsedModule{}
	e := probe.regex("ab")
	if ok, err := e.compiled("ab"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	perSearch := e.size * (n + 1)
	need := 3 + (n + 1) + 3*regexParseCost + 2 + 3*perSearch
	for _, c := range []struct {
		remaining int
		limited   bool
	}{
		{need, false},
		{need - 1, true},
	} {
		m := &ParsedModule{fnWork: maxFunctionWork - c.remaining}
		if _, limited := boundedCall(t, m, "regexall", cty.StringVal("ab"), cty.StringVal(strings.Repeat("x", n))); limited != c.limited {
			t.Errorf("regexall with %d work left: limited %v, want %v", c.remaining, limited, c.limited)
		}
	}
}

// TestReplaceMatchesGo: the regex replace builds its result from the matches it found, which
// must equal Go's ReplaceAllString, empty matches included.
func TestReplaceMatchesGo(t *testing.T) {
	t.Parallel()
	inputs := []string{"", "a", "abc", "aaa", "a-b--c", "x1y22z333", "\u00e9t\u00e9", "  a  b  "}
	patterns := []string{``, `a*`, `a`, `b*`, `-+`, `\d+`, `\s*`, `(\w)`, `(?P<n>\d)`, `^`, `$`, `\b`, `x*y|x`, `.`}
	repls := []string{"", "-", "[$0]", "$1$1", "${n}", "$$", "<$2>"}
	for _, in := range inputs {
		for _, p := range patterns {
			for _, r := range repls {
				m := &ParsedModule{}
				got, limited := boundedCall(t, m, "replace", cty.StringVal(in), cty.StringVal("/"+p+"/"), cty.StringVal(r))
				want := regexp.MustCompile(p).ReplaceAllString(cty.StringVal(in).AsString(), r)
				if limited || !got.RawEquals(cty.StringVal(want)) {
					t.Errorf("replace(%q, /%s/, %q) = %#v, Go gives %q", in, p, r, got, want)
				}
			}
		}
	}
}

// TestRegexLimits: plain replace checks its exact output size, and regex replace an upper
// bound from the matches and `$` references.
func TestRegexLimits(t *testing.T) {
	t.Parallel()
	str := func(n int) cty.Value { return cty.StringVal(strings.Repeat("x", n)) }
	call := func(m *ParsedModule, name string, args ...cty.Value) bool {
		t.Helper()
		_, limited := boundedCall(t, m, name, args...)
		return limited
	}
	// Replacing each of n "x" with "yy" gives 2n bytes, a string of size 2n+1.
	for _, c := range []struct {
		n       int
		limited bool
	}{
		{(maxFunctionValueSize - 1) / 2, false},
		{(maxFunctionValueSize-1)/2 + 1, true},
	} {
		if got := call(&ParsedModule{}, "replace", str(c.n), cty.StringVal("x"), cty.StringVal("yy")); got != c.limited {
			t.Errorf("replace over %d bytes: limited %v, want %v", c.n, got, c.limited)
		}
	}
	if !call(&ParsedModule{}, "replace", str(1000), cty.StringVal(""), cty.StringVal(strings.Repeat("y", 300))) {
		t.Error("replace inserting 300 bytes 1,001 times was not limited")
	}
	// "/xxxx/" over 40 "x" (10 matches) with r × "$0" is bounded by
	// 40 + 10 × (2r + 4r - 4) = 60r, and must stay below maxFunctionValueSize.
	for _, c := range []struct {
		r       int
		limited bool
	}{
		{(maxFunctionValueSize - 1) / 60, false},
		{(maxFunctionValueSize-1)/60 + 1, true},
	} {
		if got := call(&ParsedModule{}, "replace", str(40), cty.StringVal("/xxxx/"), cty.StringVal(strings.Repeat("$0", c.r))); got != c.limited {
			t.Errorf("regex replace with %d references: limited %v, want %v", c.r, got, c.limited)
		}
	}
}

// TestReplaceBoundsBeforeBuilding: replace refuses an oversized output before building it, so a
// call that would produce 16 MiB allocates almost nothing. Not parallel: it reads the process's
// allocation counter. Under the race detector sync.Pool drops its items, so regexp allocates a
// matcher per match while counting them; only the literal case is measured there.
func TestReplaceBoundsBeforeBuilding(t *testing.T) {
	big := strings.Repeat("y", 4096)
	for i, args := range [][]cty.Value{
		{cty.StringVal(strings.Repeat("x", 4096)), cty.StringVal(""), cty.StringVal(big)},
		{cty.StringVal(strings.Repeat("x", 4096)), cty.StringVal("/x/"), cty.StringVal(strings.Repeat("$0", 2048))},
	} {
		m := &ParsedModule{}
		f := m.functions(nil, nil)["replace"]
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		got, err := f.Call(args)
		runtime.ReadMemStats(&after)
		if err != nil || got.IsKnown() || !m.fnLimited {
			t.Fatalf("replace(%.20q…) = %#v, %v; want limited", args[1].AsString(), got, err)
		}
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 && (i == 0 || !raceEnabled) {
			t.Errorf("replace(%.20q…) allocated %d bytes before refusing", args[1].AsString(), alloc)
		}
	}
}

// TestRegexNotCompiledPastEstimate: a 4 KiB pattern of counted repetitions would compile to
// about 400,000 instructions; the estimate refuses it before compiling, so the call allocates
// little. Not parallel: it reads the process's allocation counter.
func TestRegexNotCompiledPastEstimate(t *testing.T) {
	pattern := strings.Repeat("(?:x{1000})", maxRegexPattern/11)
	m := &ParsedModule{}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, limited := boundedCall(t, m, "regexall", cty.StringVal(pattern), cty.StringVal("x"))
	runtime.ReadMemStats(&after)
	if !limited || m.regexes[pattern].re != nil {
		t.Fatalf("regexall over a 400,000-instruction pattern: limited %v", limited)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
		t.Errorf("refusing the pattern allocated %d bytes", alloc)
	}
}

// TestRegexCacheIsBounded: distinct Unicode-class patterns until the module's work runs out
// keep at most maxRegexCache patterns, without their parse trees, so the memory a module keeps
// stays small. Not parallel: it reads the heap size.
func TestRegexCacheIsBounded(t *testing.T) {
	m := &ParsedModule{}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	calls := 0
	for i := 0; m.fnWork < maxFunctionWork; i++ {
		boundedCall(t, m, "regexall", cty.StringVal(`(?i)[\pL\pN]`+strconv.Itoa(i)), cty.StringVal("x"))
		calls++
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if len(m.regexes) > maxRegexCache || calls <= maxRegexCache {
		t.Fatalf("%d calls kept %d patterns", calls, len(m.regexes))
	}
	for p, e := range m.regexes {
		if e.parsed != nil && e.re != nil {
			t.Fatalf("pattern %q keeps its parse tree after compiling", p)
		}
	}
	if kept := int64(after.HeapAlloc) - int64(before.HeapAlloc); kept > 16<<20 {
		t.Errorf("%d calls kept %d bytes of heap", calls, kept)
	}
	runtime.KeepAlive(m)
}

// TestRegexTypeAndRunAgree: with the cache full, a call's type check and its run see the same
// parse, so no remaining work makes them disagree. Before, a parse affordable for the type
// check but not for the run made the call an error, which can() turned into a known false
// where Terraform gives true.
func TestRegexTypeAndRunAgree(t *testing.T) {
	t.Parallel()
	for slack := 0; slack <= 400; slack += 7 {
		m := parseLocalsModule(t, "locals {\n  v = can(regexall(\"b\", \"x\"))\n}\n")
		for i := range maxRegexCache {
			m.regex("p" + strconv.Itoa(i))
		}
		m.fnWork = maxFunctionWork - slack
		locals, err := m.EvaluateLocals(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if v := locals["v"].Value; v.RawEquals(cty.False) {
			t.Fatalf("with %d work left, can(regexall(\"b\", \"x\")) = false; want true or unknown", slack)
		}
	}
	// The pattern past the cache is parsed and charged once per call, not once per type check.
	m := &ParsedModule{}
	for i := range maxRegexCache {
		m.regex("p" + strconv.Itoa(i))
	}
	before := m.fnWork
	boundedCall(t, m, "regexall", cty.StringVal("b"), cty.StringVal("x"))
	if got, max := m.fnWork-before, 4+regexParseCost*2+1+3*8+1; got > max {
		t.Errorf("an uncached call charged %d, more than one parse (%d)", got, max)
	}
}
