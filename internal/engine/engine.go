package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
	"golang.org/x/sync/errgroup"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// DefaultTimeout bounds the evaluation of one input document.
const DefaultTimeout = 30 * time.Second

// Options tune evaluation. The zero value uses DefaultTimeout and GOMAXPROCS workers.
type Options struct {
	// Timeout bounds each document's evaluation.
	Timeout time.Duration
	// Parallelism bounds how many documents EvaluateAll evaluates at once.
	Parallelism int
}

// Result holds one document's violations keyed by rule ID: each rule's deny set as JSON values
// (decoded into findings by the caller). Every loaded rule has a key, empty when it found nothing.
type Result map[string][]any

// EvalTimeoutError is a document whose evaluation did not finish within the timeout.
type EvalTimeoutError struct {
	RootModule string
	Timeout    time.Duration
}

func (e *EvalTimeoutError) Error() string {
	return fmt.Sprintf("policy evaluation of root module %q exceeded %s", e.RootModule, e.Timeout)
}

// Engine is a compiled policy library: one prepared query, shared read-only across goroutines.
type Engine struct {
	pq          rego.PreparedEvalQuery
	ruleByFile  map[string]string
	rules       map[string]Rule
	builtins    map[string]bool
	timeout     time.Duration
	parallelism int
}

// LoadCapabilities reads capabilities.json from fsys (policies.FS): the builtins policies may
// call.
func LoadCapabilities(fsys fs.FS) (*ast.Capabilities, error) {
	data, err := fs.ReadFile(fsys, "capabilities.json")
	if err != nil {
		return nil, &PolicyError{File: "capabilities.json", Msg: err.Error()}
	}
	caps, err := ast.LoadCapabilitiesJSON(bytes.NewReader(data))
	if err != nil {
		return nil, &PolicyError{File: "capabilities.json", Msg: err.Error()}
	}
	return caps, nil
}

// New compiles lib in strict mode against caps and prepares one query that returns every rule's
// deny set keyed by rule ID. A compile error, such as a call to a builtin caps does not allow,
// is a *PolicyError naming the file.
func New(ctx context.Context, lib *Library, caps *ast.Capabilities, opts Options) (*Engine, error) {
	if len(lib.Rules) == 0 {
		return nil, errors.New("engine: no rules to evaluate")
	}
	if caps == nil {
		// rego falls back to OPA's default capabilities, network builtins included.
		return nil, errors.New("engine: capabilities are required")
	}
	rules := slices.Clone(lib.Rules)
	slices.SortFunc(rules, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) })
	entries := make([]string, 0, len(rules))
	ruleByFile := make(map[string]string, len(rules))
	byID := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
		entries = append(entries, strconv.Quote(r.ID)+": data."+r.Package+".deny")
		ruleByFile[r.File] = r.ID
	}
	args := []func(*rego.Rego){
		rego.Query("x := {" + strings.Join(entries, ", ") + "}"),
		rego.SetRegoVersion(ast.RegoV1),
		rego.Capabilities(caps),
		rego.Strict(true),
		rego.StrictBuiltinErrors(true),
	}
	files := make([]string, 0, len(lib.Modules))
	for f := range lib.Modules {
		files = append(files, f)
	}
	slices.Sort(files)
	for _, f := range files {
		args = append(args, rego.ParsedModule(lib.Modules[f]))
	}
	pq, err := rego.New(args...).PrepareForEval(ctx)
	if err != nil {
		return nil, compileError(err)
	}
	builtins := make(map[string]bool, len(caps.Builtins))
	for _, b := range caps.Builtins {
		builtins[b.Name] = true
	}
	e := &Engine{pq: pq, ruleByFile: ruleByFile, rules: byID, builtins: builtins, timeout: opts.Timeout, parallelism: opts.Parallelism}
	if e.timeout <= 0 {
		e.timeout = DefaultTimeout
	}
	if e.parallelism <= 0 {
		e.parallelism = runtime.GOMAXPROCS(0)
	}
	return e, nil
}

// compileError names the file of the first compile error.
func compileError(err error) error {
	var errs ast.Errors
	if errors.As(err, &errs) && len(errs) > 0 && errs[0].Location != nil && errs[0].Location.File != "" {
		return &PolicyError{File: errs[0].Location.File, Msg: err.Error()}
	}
	return &PolicyError{File: "(policies)", Msg: err.Error()}
}

// Evaluate runs every rule over doc, converting it to a Rego value once. A builtin error is a
// *PolicyError naming the rule; running past the timeout is an *EvalTimeoutError.
func (e *Engine) Evaluate(ctx context.Context, doc *model.InputDocument) (Result, error) {
	if doc == nil {
		return nil, errors.New("engine: no input document")
	}
	input, err := ast.InterfaceToValue(doc)
	if err != nil {
		return nil, fmt.Errorf("engine: convert the input document of %q: %w", doc.Source.RootModule, err)
	}
	evalCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	rs, err := e.pq.Eval(evalCtx, rego.EvalParsedInput(input))
	// OPA checks for cancellation only now and then: a result is trusted only if the context
	// was still live when it returned.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if errors.Is(evalCtx.Err(), context.DeadlineExceeded) {
		return nil, &EvalTimeoutError{RootModule: doc.Source.RootModule, Timeout: e.timeout}
	}
	if err != nil {
		return nil, e.evalError(err)
	}
	if len(rs) != 1 {
		return nil, fmt.Errorf("engine: internal error: the rule query returned %d results, want 1", len(rs))
	}
	x, ok := rs[0].Bindings["x"].(map[string]any)
	if !ok {
		return nil, errors.New("engine: internal error: the rule query result is not an object")
	}
	res := make(Result, len(x))
	for id, v := range x {
		set, isList := v.([]any)
		if !isList {
			return nil, fmt.Errorf("engine: internal error: rule %s's deny is not a set", id)
		}
		res[id] = set
	}
	return res, nil
}

// evalError names the rule whose module raised an error at evaluation time. The message keeps
// only the error code, the builtin's name (when it is one caps allows) and the location: OPA's own text quotes the operand
// (to_number: parsing "<value>"), which may be a value of the scanned configuration.
func (e *Engine) evalError(err error) error {
	var te *topdown.Error
	if !errors.As(err, &te) {
		return &PolicyError{File: "(policies)", Msg: "policy evaluation failed (details withheld: they may quote scanned values)"}
	}
	msg := te.Code
	if name, _, ok := strings.Cut(te.Message, ":"); ok && e.builtins[name] {
		msg += " in " + name
	}
	if te.Location == nil {
		return &PolicyError{File: "(policies)", Msg: msg}
	}
	msg += fmt.Sprintf(" at line %d, column %d", te.Location.Row, te.Location.Col)
	return &PolicyError{File: te.Location.File, RuleID: e.ruleByFile[te.Location.File], Msg: msg}
}

// EvaluateAll evaluates docs concurrently, at most Options.Parallelism at a time, and returns
// their results in order. The first error cancels the others and is returned.
func (e *Engine) EvaluateAll(ctx context.Context, docs []*model.InputDocument) ([]Result, error) {
	results := make([]Result, len(docs))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(e.parallelism)
	for i, doc := range docs {
		g.Go(func() error {
			res, err := e.Evaluate(gctx, doc)
			results[i] = res
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}
