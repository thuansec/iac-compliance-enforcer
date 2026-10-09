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
	_, err := lexCost(name, data)
	return err
}

// lexCost is checkNesting that also returns what keeping the file's syntax costs, in budget
// tokens (ADR 0017): the lexer's tokens plus one per bytesPerToken source bytes for HCL, since a
// kept file holds its source and copies of its literals whatever its token count, and the bytes
// of a JSON file, which keep about as much tree each.
func lexCost(name string, data []byte) (int, error) {
	if strings.HasSuffix(name, ".json") {
		return len(data), checkJSONNesting(data)
	}
	tokens, _ := hclsyntax.LexConfig(data, name, hcl.InitialPos)
	return len(tokens) + (len(data)+bytesPerToken-1)/bytesPerToken, scanTokens(tokens, 0)
}

// maxChain bounds the postfix steps (`x[k][k]...`, `x.a.b...`) that nest in an expression that is
// evaluated: brackets close, so the nesting limits do not see a chain, but walking and evaluating
// it recurse once per step (T-0111c: a 1 MiB chain of 350,000 steps allocated about 600 MB and
// used 128 MB of stack). Real configurations use a handful.
const maxChain = 1024

var errChainTooLong = errors.New("index or attribute chain too long to evaluate safely")

// checkChains reports an expression whose postfix steps nest more than maxChain deep. An index
// (`[`) or attribute (`.`) step right after a value (a name, a number, a splat `*`, or a closing
// bracket, parenthesis or quote) continues the chain. The count adds up through nesting, as the
// syntax tree's depth does: a bracket's content starts at the count where it opens, and the
// deepest count inside it carries out when it closes, so a chain wrapped in parentheses, in an
// index key or in call arguments still counts as one. Comments and newlines are skipped; any other
// token ends the chain at its level.
func checkChains(tokens hclsyntax.Tokens) error {
	type level struct {
		base, cur, deepest int  // the count where the level opened, now, and the deepest inside it
		end                bool // the previous token at this level ends a value
		step               bool // the previous token at this level is a `.` step
	}
	stack := []level{{}}
	for _, tok := range tokens {
		top := &stack[len(stack)-1]
		switch tok.Type {
		case hclsyntax.TokenOBrack, hclsyntax.TokenDot:
			if top.end {
				top.cur++
				top.deepest = max(top.deepest, top.cur)
				if top.cur > maxChain {
					return fmt.Errorf("%w: more than %d steps at line %d", errChainTooLong, maxChain, tok.Range.Start.Line)
				}
			} else {
				top.cur = top.base
			}
			top.end, top.step = false, tok.Type == hclsyntax.TokenDot && top.end
			if tok.Type == hclsyntax.TokenOBrack {
				stack = append(stack, level{base: top.cur, cur: top.cur, deepest: top.cur})
			}
		case hclsyntax.TokenOBrace, hclsyntax.TokenOParen, hclsyntax.TokenTemplateInterp,
			hclsyntax.TokenTemplateControl, hclsyntax.TokenOQuote, hclsyntax.TokenOHeredoc:
			top.cur, top.end, top.step = top.base, false, false // only `[` and `.` continue a chain
			stack = append(stack, level{base: top.cur, cur: top.cur, deepest: top.cur})
		case hclsyntax.TokenCBrack, hclsyntax.TokenCBrace, hclsyntax.TokenCParen,
			hclsyntax.TokenTemplateSeqEnd, hclsyntax.TokenCQuote, hclsyntax.TokenCHeredoc:
			deepest := top.deepest
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			top = &stack[len(stack)-1]
			top.cur = max(top.cur, deepest)
			top.deepest = max(top.deepest, top.cur)
			top.end, top.step = true, false
		case hclsyntax.TokenIdent, hclsyntax.TokenNumberLit, hclsyntax.TokenStar:
			if !top.step {
				if tok.Type == hclsyntax.TokenStar {
					top.cur, top.end = top.base, false // multiplication, or `[*]`, whose `[` counted
					continue
				}
				top.cur = top.base // a new value starts
			}
			top.end, top.step = true, false
		case hclsyntax.TokenComment, hclsyntax.TokenNewline:
			// The parser skips comments, and newlines inside brackets, between the steps of one
			// chain: neither ends it. Skipping newlines everywhere can only over-count.
		default:
			top.cur, top.end, top.step = top.base, false, false
		}
	}
	return nil
}

// scanTokens applies the nesting limits to a token stream and, when maxOps is positive (an
// expression about to be evaluated), caps the number of binary operators (evaluating an operator
// chain recurses once per operand) and the length of postfix chains (checkChains).
func scanTokens(tokens hclsyntax.Tokens, maxOps int) error {
	if maxOps > 0 {
		if err := checkChains(tokens); err != nil {
			return err
		}
	}
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
