package terraform

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// The HCL and JSON parsers recurse once per nesting level, and Go turns an exhausted stack into
// a fatal error that recover cannot catch: a few hundred kilobytes of "[[[[", "!!!!" or
// "x?1:x?1:..." kill the process (hcl v2.25.0 crashes between 300,000 and 600,000 levels).
// checkNesting bounds the recursion before anything is parsed. Real configurations stay far
// below these limits. Binary operator chains are parsed without recursion, but evaluating them
// recurses: callers must not evaluate untrusted expressions without their own bound.
const (
	// maxNesting bounds open brackets, braces, parentheses, quotes, heredocs and template
	// sequences, plus the open conditional operators and the run of unary operators.
	maxNesting = 512
	// maxSplats bounds splat operators ([*] and .*) per file; a chain of them recurses.
	maxSplats = 4096
)

var errTooDeep = errors.New("nesting too deep to parse safely")

// nestingError is errTooDeep with the line where the limit was crossed (0 for JSON).
type nestingError struct {
	msg  string
	line int
}

func (e *nestingError) Error() string { return e.msg }
func (e *nestingError) Unwrap() error { return errTooDeep }

// checkNesting reports whether a file can be parsed without unbounded recursion. It works on the
// lexer's tokens (HCL) or a byte scan (JSON), neither of which recurses.
//
// A conditional "c ? a : b" recurses into its branches, so every "?" stays open until its
// expression can end: at a comma or "=" (the next list item, argument or attribute) in the same
// bracket, or when that bracket closes. Newlines never close one, because the parser ignores
// them inside parentheses and brackets.
func checkNesting(name string, data []byte) error {
	if strings.HasSuffix(name, ".json") {
		return checkJSONNesting(data)
	}
	tokens, _ := hclsyntax.LexConfig(data, name, hcl.InitialPos)
	return scanTokens(tokens, 0)
}

// scanTokens applies the nesting limits to a token stream and, when maxOps is positive, caps the
// number of binary operators (evaluating an operator chain recurses once per operand).
func scanTokens(tokens hclsyntax.Tokens, maxOps int) error {
	open := []int{0} // per open bracket, the conditionals open inside it; [0] is the outermost level
	conditionals, unary, splats, ops := 0, 0, 0, 0
	for i, tok := range tokens {
		top := len(open) - 1
		switch tok.Type {
		case hclsyntax.TokenOBrace, hclsyntax.TokenOBrack, hclsyntax.TokenOParen,
			hclsyntax.TokenTemplateInterp, hclsyntax.TokenTemplateControl,
			hclsyntax.TokenOQuote, hclsyntax.TokenOHeredoc:
			open = append(open, 0)
		case hclsyntax.TokenCBrace, hclsyntax.TokenCBrack, hclsyntax.TokenCParen,
			hclsyntax.TokenTemplateSeqEnd, hclsyntax.TokenCQuote, hclsyntax.TokenCHeredoc:
			if top > 0 {
				conditionals -= open[top]
				open = open[:top]
			}
		case hclsyntax.TokenQuestion:
			open[top]++
			conditionals++
		case hclsyntax.TokenComma, hclsyntax.TokenEqual:
			conditionals -= open[top]
			open[top] = 0
		case hclsyntax.TokenStar:
			if i > 0 && (tokens[i-1].Type == hclsyntax.TokenOBrack || tokens[i-1].Type == hclsyntax.TokenDot) {
				splats++
			} else {
				ops++
			}
		case hclsyntax.TokenPlus, hclsyntax.TokenMinus, hclsyntax.TokenSlash, hclsyntax.TokenPercent,
			hclsyntax.TokenEqualOp, hclsyntax.TokenNotEqual, hclsyntax.TokenLessThan, hclsyntax.TokenLessThanEq,
			hclsyntax.TokenGreaterThan, hclsyntax.TokenGreaterThanEq, hclsyntax.TokenAnd, hclsyntax.TokenOr:
			ops++
		default: // other tokens do not nest
		}
		if tok.Type == hclsyntax.TokenBang || tok.Type == hclsyntax.TokenMinus {
			unary++
		} else {
			unary = 0
		}
		if len(open)-1+conditionals+unary > maxNesting {
			return &nestingError{
				msg:  fmt.Sprintf("%v: more than %d levels at line %d", errTooDeep, maxNesting, tok.Range.Start.Line),
				line: tok.Range.Start.Line,
			}
		}
		if splats > maxSplats {
			return fmt.Errorf("%w: more than %d splat operators", errTooDeep, maxSplats)
		}
		if maxOps > 0 && ops > maxOps {
			return fmt.Errorf("%w: more than %d operators", errTooDeep, maxOps)
		}
	}
	return nil
}

// checkJSONNesting bounds array and object nesting, skipping string contents.
func checkJSONNesting(data []byte) error {
	depth, inString, escaped := 0, false, false
	for _, b := range data {
		switch {
		case inString && escaped:
			escaped = false
		case inString && b == '\\':
			escaped = true
		case inString && b == '"':
			inString = false
		case inString:
		case b == '"':
			inString = true
		case b == '[' || b == '{':
			depth++
			if depth > maxNesting {
				return fmt.Errorf("%w: more than %d levels", errTooDeep, maxNesting)
			}
		case b == ']' || b == '}':
			depth = max(depth-1, 0)
		}
	}
	return nil
}
