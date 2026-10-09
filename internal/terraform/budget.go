package terraform

import "sync"

// MaxScanTokens is the default parse budget of a scan, in budget tokens (lexCost, ADR 0017). A
// kept file holds at most about 135 bytes per budget token (TestKeptHeapPerBudgetToken: an
// operator chain), so 3,000,000 tokens are at most about 400 MB, which leaves room in the 1 GiB
// scan budget for one file's transient parse peak (about 450 MB, ADR 0016). Realistic Terraform
// costs about 380,000 budget tokens per MiB.
const MaxScanTokens = 3_000_000

// bytesPerToken charges one budget token per this many source bytes, on top of the lexer's
// tokens: a kept file holds its source, and its long literals hold a copy (about 3 bytes per
// source byte, against about 90 per token).
const bytesPerToken = 30

// DiagParseLimit reports a file that is not parsed or checked because the scan's parse budget is
// used up.
const DiagParseLimit DiagCode = "parse_limit"

// ParseBudget bounds the syntax trees one scan keeps, in budget tokens (lexCost). It is safe for concurrent
// use; a nil budget takes everything.
type ParseBudget struct {
	mu        sync.Mutex
	limit     int
	remaining int
}

// NewParseBudget returns a budget of tokens.
func NewParseBudget(tokens int) *ParseBudget {
	return &ParseBudget{limit: tokens, remaining: tokens}
}

// take reserves n tokens and reports whether they fit; a refusal reserves nothing.
func (b *ParseBudget) take(n int) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.remaining {
		return false
	}
	b.remaining -= n
	return true
}

// size returns the budget's size in tokens.
func (b *ParseBudget) size() int {
	if b == nil {
		return 0
	}
	return b.limit
}
