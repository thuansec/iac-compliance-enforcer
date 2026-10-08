package terraform

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// Limits on regular expressions. Go's RE2 engine matches in time proportional to program size
// × input length per search, but finding all matches searches again after each one, and
// compiling a counted repetition expands it: `(?:a{30}){30}` compiles to hundreds of
// instructions. Terraform patterns are a few dozen bytes and instructions.
const (
	// maxRegexPattern bounds a pattern's length before it is parsed: parsing a Unicode class
	// copies its table, so parsing costs far more than the pattern's length.
	maxRegexPattern = 4 << 10
	// regexParseCost is the work charged per pattern byte for parsing and compiling it, once
	// per distinct pattern in a module.
	regexParseCost = 64
	// maxRegexProgram bounds a pattern's compiled program, in instructions.
	maxRegexProgram = 1 << 12
	// maxRegexCache bounds the patterns a module keeps compiled; past it, patterns are parsed
	// and compiled for each call (and charged each time). A Unicode class holds thousands of
	// runes, so the cache, not the work charged, bounds the memory kept.
	maxRegexCache = 256
)

// errRegexLimit makes a regex call unknown with a function_limit warning.
var errRegexLimit = errors.New("regular expression over a limit")

// regexEntry is a pattern parsed (and, once a call needs it, compiled) for this module.
type regexEntry struct {
	// over: the pattern passes a regex limit, or the work to parse it was not available.
	over bool
	err  error
	// ty is the type of one match: a string, a tuple of strings for unnamed groups, or an
	// object of strings for named groups.
	ty     cty.Type
	caps   int
	names  []string
	parsed *syntax.Regexp
	re     *regexp.Regexp
	size   int
}

// regex parses pattern, charging the parse by the pattern's length and by the runes its classes
// expand to. A module keeps up to maxRegexCache patterns; others are parsed for each call (the
// last one is kept, so a call's type check and its run share one parse). The
// estimate of the compiled size (regexSize) refuses anything far over maxRegexProgram before
// anything is compiled; compiled then checks the real size.
func (m *ParsedModule) regex(pattern string) *regexEntry {
	if e, ok := m.regexes[pattern]; ok {
		return e
	}
	if m.lastRegex != nil && m.lastRegexPattern == pattern {
		return m.lastRegex
	}
	e := &regexEntry{}
	if len(m.regexes) < maxRegexCache {
		if m.regexes == nil {
			m.regexes = map[string]*regexEntry{}
		}
		m.regexes[pattern] = e
	} else {
		// One call checks its type and then runs, each asking for the pattern: they must see
		// the same entry, or a parse affordable for one and not the other gives two types.
		m.lastRegex, m.lastRegexPattern = e, pattern
	}
	if len(pattern) > maxRegexPattern || !m.chargeFunctionWork(saturatingMul(len(pattern)+1, regexParseCost)) {
		e.over = true
		return e
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		// The error quotes the pattern; it only reaches hcl's Detail, which iace drops.
		e.err = fmt.Errorf("invalid regexp pattern: %w", err)
		return e
	}
	if !m.chargeFunctionWork(regexRunes(parsed)) || regexSize(parsed) > 2*maxRegexProgram {
		e.over = true
		return e
	}
	e.parsed, e.caps = parsed, parsed.MaxCap()
	e.names = make([]string, e.caps)
	copy(e.names, parsed.CapNames()[1:])
	e.ty, e.err = regexMatchType(e.names)
	return e
}

// compiled compiles e's pattern once, and reports false when its program passes
// maxRegexProgram.
func (e *regexEntry) compiled(pattern string) (bool, error) {
	if e.re != nil {
		return true, nil
	}
	if e.over {
		return false, nil
	}
	prog, err := syntax.Compile(e.parsed.Simplify())
	if err != nil {
		return false, fmt.Errorf("invalid regexp pattern: %w", err)
	}
	if len(prog.Inst) > maxRegexProgram {
		e.over = true
		return false, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regexp pattern: %w", err)
	}
	e.re, e.size, e.parsed = re, len(prog.Inst), nil
	return true, nil
}

// regexRunes counts the runes in re's literals and classes, which parsing expands Unicode
// classes into and the compiled program keeps.
func regexRunes(re *syntax.Regexp) int {
	n := len(re.Rune)
	for _, sub := range re.Sub {
		n += regexRunes(sub)
	}
	return n
}

// regexMatchType is the type of one match, as go-cty's (and so Terraform's) regex returns it.
func regexMatchType(names []string) (cty.Type, error) {
	named, unnamed := 0, 0
	for _, n := range names {
		if n == "" {
			unnamed++
		} else {
			named++
		}
	}
	switch {
	case named == 0 && unnamed == 0:
		return cty.String, nil
	case named > 0 && unnamed > 0:
		return cty.NilType, errors.New("invalid regexp pattern: cannot mix both named and unnamed capture groups")
	case unnamed > 0:
		ety := make([]cty.Type, unnamed)
		for i := range ety {
			ety[i] = cty.String
		}
		return cty.Tuple(ety), nil
	}
	atys := make(map[string]cty.Type, named)
	for _, n := range names {
		atys[n] = cty.String
	}
	return cty.Object(atys), nil
}

// regexSize estimates the instructions re compiles to, as Simplify and Compile expand it, and
// never less: one per literal rune or other leaf, one or two per operator, x{n,m} as m copies
// of x with a choice before each, x{n,} as n copies plus x*, and two for the whole program. It
// saturates just above 2*maxRegexProgram. The parser bounds the tree's depth.
func regexSize(re *syntax.Regexp) int {
	return min(regexNodeSize(re)+2, 2*maxRegexProgram+1)
}

func regexNodeSize(re *syntax.Regexp) int {
	const limit = 2*maxRegexProgram + 1
	sum := func(subs []*syntax.Regexp) int {
		n := 0
		for _, sub := range subs {
			n = min(n+regexNodeSize(sub), limit)
		}
		return n
	}
	switch re.Op {
	case syntax.OpLiteral:
		return min(len(re.Rune), limit)
	case syntax.OpConcat:
		return sum(re.Sub)
	case syntax.OpAlternate:
		return min(sum(re.Sub)+len(re.Sub)-1, limit)
	case syntax.OpCapture:
		return min(sum(re.Sub)+2, limit)
	case syntax.OpStar:
		return min(sum(re.Sub)+2, limit) // x* over a nullable x compiles as (x+)?
	case syntax.OpPlus, syntax.OpQuest:
		return min(sum(re.Sub)+1, limit)
	case syntax.OpRepeat:
		sub := sum(re.Sub)
		if re.Max < 0 {
			return min(saturatingMul(re.Min, sub)+sub+2, limit)
		}
		return min(saturatingMul(re.Max, sub+1), limit)
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpCharClass, syntax.OpAnyCharNotNL,
		syntax.OpAnyChar, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 1
	}
	return 1
}

// findAll returns e's matches in str as Go's FindAllStringSubmatchIndex(str, limit) does, or
// errRegexLimit when the searches could cost more than the module's remaining work or the
// matches could be more than a result holds (limit < 0 means all of them). One search costs at
// most program size × (groups + 1) × (len(str) + 1): the engine copies the groups for each
// thread. Finding k matches searches at most 2k + 1 times, since an empty match right after a
// match is skipped and searched past. The searches made are charged.
func (m *ParsedModule) findAll(e *regexEntry, str string, limit int) ([][]int, error) {
	perSearch := saturatingMul(saturatingMul(e.size, e.caps+1), len(str)+1)
	affordable := ((maxFunctionWork-m.fnWork)/perSearch - 1) / 2
	capped := limit < 0 || limit > affordable
	if capped {
		limit = min(affordable, maxFunctionValueSize/(e.caps+1)+1)
	}
	if limit < 1 {
		m.spendFunctionWork(perSearch)
		return nil, errRegexLimit
	}
	matches := e.re.FindAllStringSubmatchIndex(str, limit)
	m.spendFunctionWork(saturatingMul(2*len(matches)+1, perSearch))
	if capped && len(matches) == limit {
		return nil, errRegexLimit // there may be more
	}
	return matches, nil
}

// matchValue is one match as go-cty's regex returns it: a group that took no part in the match
// is null.
func matchValue(e *regexEntry, str string, idx []int) cty.Value {
	if e.ty == cty.String {
		return cty.StringVal(str[idx[0]:idx[1]])
	}
	group := func(i int) cty.Value {
		start, end := idx[2*i+2], idx[2*i+3]
		if start < 0 || end < 0 {
			return cty.NullVal(cty.String)
		}
		return cty.StringVal(str[start:end])
	}
	if e.ty.IsTupleType() {
		vals := make([]cty.Value, e.caps)
		for i := range vals {
			vals[i] = group(i)
		}
		return cty.TupleVal(vals)
	}
	vals := make(map[string]cty.Value, e.caps)
	for i, n := range e.names {
		vals[n] = group(i)
	}
	return cty.ObjectVal(vals)
}

// regexFunc returns Terraform's regex (all false) or regexall (all true) for this module: the
// types and results of go-cty's RegexFunc and RegexAllFunc, with every limit checked before
// the work it bounds. findAll caps the matches at what a result can hold, so building it is
// bounded; the bounded wrapper then checks its size.
func (m *ParsedModule) regexFunc(all bool) function.Function {
	resultType := func(ty cty.Type) cty.Type {
		if all {
			return cty.List(ty)
		}
		return ty
	}
	return function.New(&function.Spec{
		Description: "Applies a regular expression to a string and returns its first match, or all of them.",
		Params: []function.Parameter{
			{Name: "pattern", Type: cty.String},
			{Name: "string", Type: cty.String},
		},
		Type: func(args []cty.Value) (cty.Type, error) {
			if !args[0].IsKnown() {
				return resultType(cty.DynamicPseudoType), nil
			}
			e := m.regex(args[0].AsString())
			switch {
			case e.err != nil:
				return cty.NilType, function.NewArgError(0, e.err)
			case e.over:
				return resultType(cty.DynamicPseudoType), nil
			}
			return resultType(e.ty), nil
		},
		RefineResult: func(b *cty.RefinementBuilder) *cty.RefinementBuilder { return b.NotNull() },
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			limited := func() (cty.Value, error) {
				m.fnLimited = true
				return cty.UnknownVal(retType), nil
			}
			pattern, str := args[0].AsString(), args[1].AsString()
			e := m.regex(pattern)
			if ok, err := e.compiled(pattern); err != nil {
				return cty.NilVal, function.NewArgError(0, err)
			} else if !ok {
				return limited()
			}
			limit := 1
			if all {
				limit = -1
			}
			matches, err := m.findAll(e, str, limit)
			if err != nil {
				return limited()
			}
			if !all {
				if len(matches) == 0 {
					return cty.NilVal, errors.New("pattern did not match any part of the given string")
				}
				return matchValue(e, str, matches[0]), nil
			}
			if len(matches) == 0 {
				return cty.ListValEmpty(e.ty), nil
			}
			vals := make([]cty.Value, len(matches))
			for i, idx := range matches {
				vals[i] = matchValue(e, str, idx)
			}
			return cty.ListVal(vals), nil
		},
	})
}

// replaceFunc returns Terraform's replace for this module: a substring wrapped in slashes is a
// regular expression whose matches are replaced with $-expansion, as Go's ReplaceAllString
// does; any other substring is replaced literally. The output size is checked before it is
// built: exactly for a literal substring, and for a regular expression from the matches found,
// as the unmatched text plus, per match, the replacement with each `$` reference expanding to
// at most the match.
func (m *ParsedModule) replaceFunc() function.Function {
	return function.New(&function.Spec{
		Description: "Replaces each occurrence of a substring, or of a /regular expression/, in a string.",
		Params: []function.Parameter{
			{Name: "str", Type: cty.String},
			{Name: "substr", Type: cty.String},
			{Name: "replace", Type: cty.String},
		},
		Type:         function.StaticReturnType(cty.String),
		RefineResult: func(b *cty.RefinementBuilder) *cty.RefinementBuilder { return b.NotNull() },
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			str, substr, repl := args[0].AsString(), args[1].AsString(), args[2].AsString()
			limited := func() (cty.Value, error) {
				m.fnLimited = true
				return cty.UnknownVal(cty.String), nil
			}
			if len(substr) < 2 || substr[0] != '/' || substr[len(substr)-1] != '/' {
				count := strings.Count(str, substr) // for "", one more than the runes
				if len(str)+saturatingMul(count, len(repl))-count*len(substr) >= maxFunctionValueSize {
					return limited()
				}
				return cty.StringVal(strings.ReplaceAll(str, substr, repl)), nil
			}
			pattern := substr[1 : len(substr)-1]
			e := m.regex(pattern)
			if e.err != nil {
				return cty.NilVal, function.NewArgError(1, e.err)
			}
			if ok, err := e.compiled(pattern); err != nil {
				return cty.NilVal, function.NewArgError(1, err)
			} else if !ok {
				return limited()
			}
			matches, err := m.findAll(e, str, -1)
			if err != nil {
				return limited()
			}
			refs := strings.Count(repl, "$")
			out := len(str)
			for _, idx := range matches {
				n := idx[1] - idx[0]
				if out += len(repl) + saturatingMul(refs, n) - n; out >= maxFunctionValueSize {
					return limited()
				}
			}
			// The result from the matches found, as ReplaceAllString builds it.
			dst := make([]byte, 0, out)
			last := 0
			for _, idx := range matches {
				dst = append(dst, str[last:idx[0]]...)
				dst = e.re.ExpandString(dst, repl, str, idx)
				last = idx[1]
			}
			return cty.StringVal(string(append(dst, str[last:]...))), nil
		},
	})
}
