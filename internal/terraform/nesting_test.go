package terraform

import (
	"errors"
	"strings"
	"testing"
)

// deep builds inputs that crash the HCL or JSON parser with a fatal stack overflow when they are
// nested far enough (about 300,000 levels, measured with hcl v2.25.0), here at n levels.
func deep(kind string, n int) (name, src string) {
	switch kind {
	case "brackets":
		return "x.tf", "a = " + strings.Repeat("[", n) + strings.Repeat("]", n) + "\n"
	case "parens":
		return "x.tf", "a = " + strings.Repeat("(", n) + "x" + strings.Repeat(")", n) + "\n"
	case "blocks":
		return "x.tf", strings.Repeat("b {\n", n) + strings.Repeat("}\n", n)
	case "templates":
		return "x.tf", "a = " + strings.Repeat("\"${", n) + "x" + strings.Repeat("}\"", n) + "\n"
	case "for":
		return "x.tf", "a = " + strings.Repeat("[for x in ", n) + "y" + strings.Repeat(" : x]", n) + "\n"
	case "bang":
		return "x.tf", "a = " + strings.Repeat("!", n) + "true\n"
	case "minus":
		return "x.tf", "a = " + strings.Repeat("-", n) + "1\n"
	case "splat":
		return "x.tf", "a = x" + strings.Repeat("[*].y", n) + "\n"
	case "attr-splat":
		return "x.tf", "a = x" + strings.Repeat(".*.y", n) + "\n"
	case "tern-false":
		return "x.tf", "a = " + strings.Repeat("x ? 1 : ", n) + "1\n"
	case "tern-true":
		return "x.tf", "a = " + strings.Repeat("x ? ", n) + "1" + strings.Repeat(" : 1", n) + "\n"
	case "tern-lines":
		return "x.tf", "a = (" + strings.Repeat("x ?\n1 :\n", n) + "1)\n"
	case "json":
		return "x.tf.json", `{"a": ` + strings.Repeat("[", n) + strings.Repeat("]", n) + "}"
	}
	panic("unknown kind " + kind)
}

func TestCheckNestingRejectsRecursionBombs(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"brackets", "parens", "blocks", "templates", "for", "bang", "minus", "splat", "attr-splat", "tern-false", "tern-true", "tern-lines", "json"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			n := 10 * maxNesting // the guard trips long before the parser would crash
			if kind == "splat" || kind == "attr-splat" {
				n = maxSplats + 1
			}
			name, src := deep(kind, n)
			if err := checkNesting(name, []byte(src)); !errors.Is(err, errTooDeep) {
				t.Errorf("checkNesting(%s × %d) = %v, want errTooDeep", kind, n, err)
			}
			// The bomb must not crash classification: its module calls are just not read.
			if got := moduleSources(name, []byte(src)); got != nil {
				t.Errorf("moduleSources(%s bomb) = %v, want nil", kind, got)
			}
		})
	}
}

func TestCheckNestingAcceptsTheLimit(t *testing.T) {
	t.Parallel()
	tests := map[string]int{
		// "a = [[...]]": the brackets alone reach the limit.
		"brackets": maxNesting,
		"json":     maxNesting - 1, // inside the top-level object
		"splat":    maxSplats,
		"bang":     maxNesting,
		// "a = x ? 1 : x ? 1 : ... 1": each link leaves one conditional open.
		"tern-false": maxNesting,
	}
	for kind, n := range tests {
		name, src := deep(kind, n)
		if err := checkNesting(name, []byte(src)); err != nil {
			t.Errorf("checkNesting(%s × %d) = %v, want nil", kind, n, err)
		}
		over, overSrc := deep(kind, n+1)
		if err := checkNesting(over, []byte(overSrc)); !errors.Is(err, errTooDeep) {
			t.Errorf("checkNesting(%s × %d) = %v, want errTooDeep", kind, n+1, err)
		}
	}
}

func TestCheckNestingIgnoresBracketsInStrings(t *testing.T) {
	t.Parallel()
	hclSrc := `a = "` + strings.Repeat("[{(", 2000) + `"` + "\n# " + strings.Repeat("[", 2000) + "\n"
	if err := checkNesting("x.tf", []byte(hclSrc)); err != nil {
		t.Errorf("checkNesting(brackets inside a string and a comment) = %v, want nil", err)
	}
	jsonSrc := `{"a": "` + strings.Repeat(`[\"{`, 2000) + `"}`
	if err := checkNesting("x.tf.json", []byte(jsonSrc)); err != nil {
		t.Errorf("checkNesting(json brackets inside a string) = %v, want nil", err)
	}
	// Closers inside strings must not hide real nesting.
	hiding := "a = " + strings.Repeat(`["]",`, maxNesting+1) + strings.Repeat("]", maxNesting+1) + "\n"
	if err := checkNesting("x.tf", []byte(hiding)); !errors.Is(err, errTooDeep) {
		t.Errorf("checkNesting(nesting hidden behind quoted closers) = %v, want errTooDeep", err)
	}
}

func TestCheckNestingClosesConditionals(t *testing.T) {
	t.Parallel()
	// Many conditionals that each end at a comma, a new attribute or a closing bracket are fine.
	var b strings.Builder
	for range 4 * maxNesting {
		b.WriteString("a = x ? 1 : 2\n")
	}
	b.WriteString("l = [" + strings.Repeat("x ? 1 : 2, ", 4*maxNesting) + "]\n")
	b.WriteString("f = g(" + strings.Repeat("(x ? 1 : 2) + ", 4*maxNesting) + "1)\n")
	if err := checkNesting("x.tf", []byte(b.String())); err != nil {
		t.Errorf("checkNesting(many closed conditionals) = %v, want nil", err)
	}
}

func TestModuleSourcesNeverEvaluates(t *testing.T) {
	t.Parallel()
	tests := map[string][]string{
		"module \"m\" {\n  source = \"./net\"\n}\n":          {"./net"},
		"module \"m\" {\n  source = \"./${var.x}\"\n}\n":     nil,
		"module \"m\" {\n  source = \"./a\" == \"./a\"\n}\n": nil,
		"module \"m\" {\n  source = 42\n}\n":                 nil,
		"module \"m\" {\n  source = upper(\"./a\")\n}\n":     nil,
		// Evaluates to "./a" without any context: only a literal check rejects it. Evaluating
		// untrusted expressions is unsafe ("1+1+...+1" recurses once per operand).
		"module \"m\" {\n  source = true ? \"./a\" : \"./b\"\n}\n": nil,
	}
	for src, want := range tests {
		got := moduleSources("x.tf", []byte(src))
		if len(got) != len(want) || (len(want) == 1 && got[0] != want[0]) {
			t.Errorf("moduleSources(%q) = %v, want %v", src, got, want)
		}
	}
	json := map[string][]string{
		`{"module": {"m": {"source": "./net"}}}`:      {"./net"},
		`{"module": {"m": {"source": "./${var.x}"}}}`: {"./${var.x}"}, // a literal path; it names no directory
		`{"module": {"m": {"source": 42}}}`:           nil,
	}
	for src, want := range json {
		got := moduleSources("x.tf.json", []byte(src))
		if len(got) != len(want) || (len(want) == 1 && got[0] != want[0]) {
			t.Errorf("moduleSources(%q) = %v, want %v", src, got, want)
		}
	}
}
