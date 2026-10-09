package terraform

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// tooComplex evaluates local "x" = expr and reports whether it was refused as too complex.
func tooComplex(t *testing.T, expr string) bool {
	t.Helper()
	m := parseLocalsModule(t, "locals {\n  x = "+expr+"\n}\n")
	if _, err := m.EvaluateLocals(context.Background(), map[string]Variable{}); err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(diagCodes(m), func(c DiagCode) bool { return c == DiagExpressionTooComplex })
}

// Postfix chains are evaluated up to maxChain steps; one more makes the expression too complex.
// A chain ends at any other token, so two chains joined by an operator count apart.
func TestIndexChainsAreBounded(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		expr    string
		refused bool
	}{
		"index at the limit":     {"aws_x.y" + strings.Repeat("[0]", maxChain-1), false},
		"index past the limit":   {"aws_x.y" + strings.Repeat("[0]", maxChain), true},
		"var index at the limit": {"aws_x.y" + strings.Repeat("[local.k]", maxChain/2-1) + "[0]", false},
		"var index past":         {"aws_x.y" + strings.Repeat("[local.k]", maxChain/2), true},
		// A key's own steps nest inside its index step, so `[local.k]` counts two.
		// Comments and newlines between the steps do not end a chain: hcl skips them.
		"comments at the limit":    {"aws_x.y" + strings.Repeat("/**/[local.k]", maxChain/2-1) + "[0]", false},
		"comments past":            {"aws_x.y" + strings.Repeat("/**/[local.k]", maxChain/2), true},
		"newlines in parens past":  {"(aws_x.y" + strings.Repeat("\n[local.k]", maxChain/2) + ")", true},
		"newlines in tuple past":   {"[aws_x.y" + strings.Repeat("\n[local.k]", maxChain/2) + "]", true},
		"newlines at the limit":    {"(aws_x.y" + strings.Repeat("\n[local.k]", maxChain/2-1) + "\n[0])", false},
		"hash comments past":       {"(aws_x.y" + strings.Repeat(" # c\n[local.k]", maxChain/2) + ")", true},
		"attribute at the limit":   {"aws_x" + strings.Repeat(".a", maxChain), false},
		"attribute past":           {"aws_x" + strings.Repeat(".a", maxChain+1), true},
		"two chains":               {"aws_x.y" + strings.Repeat("[0]", maxChain-1) + " + aws_x.y" + strings.Repeat("[0]", maxChain-1), false},
		"call result at the limit": {"keys({})" + strings.Repeat("[0]", maxChain), false},
		"call result chain":        {"keys({})" + strings.Repeat("[0]", maxChain+1), true},
		// The count adds up through parentheses, splats, index keys and call arguments, as the
		// syntax tree's depth does.
		"parens at the limit": {"(aws_x.y" + strings.Repeat("[0]", 511) + ")" + strings.Repeat("[0]", 512), false},
		"parens past":         {"(aws_x.y" + strings.Repeat("[0]", 511) + ")" + strings.Repeat("[0]", 513), true},
		"nested parens past": {
			"((aws_x.y" + strings.Repeat("[0]", 400) + ")" + strings.Repeat("[0]", 400) + ")" + strings.Repeat("[0]", 400), true,
		},
		"splats at the limit":    {"aws_x.y" + strings.Repeat("[local.k].*", 341), false},
		"splats past":            {"aws_x.y" + strings.Repeat("[local.k].*", 341) + "[0]", true},
		"full splats past":       {"aws_x.y" + strings.Repeat("[*].a", 512), true},
		"index key at the limit": {"aws_x.y[aws_x.y" + strings.Repeat("[0]", 1021) + "]", false},
		"index key past":         {"aws_x.y[aws_x.y" + strings.Repeat("[0]", 1022) + "]", true},
		"call args at the limit": {"keys(aws_x.y" + strings.Repeat("[0]", 600) + ")" + strings.Repeat("[0]", 423), false},
		"call args past":         {"keys(aws_x.y" + strings.Repeat("[0]", 600) + ")" + strings.Repeat("[0]", 424), true},
		"sibling args":           {"concat(aws_x.y" + strings.Repeat("[0]", 1000) + ", aws_x.y" + strings.Repeat("[0]", 1000) + ")", false},
		"many interpolations":    {`"` + strings.Repeat("${aws_x.y}", 2*maxChain) + `"`, false},
		"multiplied chains":      {"aws_x.y" + strings.Repeat("[0]", 1000) + " * aws_x.y" + strings.Repeat("[0]", 1000), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tooComplex(t, tc.expr); got != tc.refused {
				t.Errorf("refused %v, want %v", got, tc.refused)
			}
		})
	}
}

// A 1 MiB chain (about 350,000 steps) is refused as too complex, so it is never walked or
// evaluated.
func TestLongestChainIsRefused(t *testing.T) {
	t.Parallel()
	expr := "aws_x.y" + strings.Repeat("[0]", (int(DefaultLimits().MaxFileSize)-64)/3)
	if !tooComplex(t, expr) {
		t.Error("a 1 MiB chain was evaluated")
	}
}
