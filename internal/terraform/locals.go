package terraform

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// Diagnostic codes for local evaluation.
const (
	// DiagLocalCycle: a local depends on itself through other locals. Terraform rejects the
	// module; the local is unknown.
	DiagLocalCycle DiagCode = "local_cycle"
	// DiagDuplicateLocal: a local is declared twice. Terraform rejects the module.
	DiagDuplicateLocal DiagCode = "duplicate_local"
	// DiagEvaluation: an expression could not be evaluated (an unsupported function or an
	// invalid reference, for example), so its value is unknown.
	DiagEvaluation DiagCode = "evaluation"
	// DiagValueTooLarge: a local's value would pass the size or nesting limit for evaluated
	// values, so it is unknown.
	DiagValueTooLarge DiagCode = "value_too_large"
	// DiagReferencesIncomplete: the locals together refer to more resources than iace records,
	// so some locals' References are incomplete.
	DiagReferencesIncomplete DiagCode = "references_incomplete"
)

// Limits on local evaluation. A local can use other locals several times, so values could
// otherwise double with every local; sizes count one unit per value plus one per string byte,
// map key or attribute name.
const (
	// maxLocalValueSize bounds one local's value.
	maxLocalValueSize = 1 << 18
	// maxLocalsSize bounds the values of all of a module's locals together.
	maxLocalsSize = 1 << 22
	// maxReferenceEntries bounds the references stored across all locals.
	maxReferenceEntries = 1 << 17
	// maxUnknownPaths and maxUnknownPathSteps bound Local.Unknown.
	maxUnknownPaths     = 1 << 10
	maxUnknownPathSteps = 1 << 12
)

// Local is a local value.
type Local struct {
	Name string
	// Value is unknown, wholly or in part, where it depends on something iace cannot know
	// statically: resources, data sources, modules, unset variables, cycles or failed
	// evaluation. Values derived from sensitive variables keep SensitiveMark.
	Value cty.Value
	// Unknown lists the outermost unknown paths in Value, in value order; an empty path means
	// the whole value. An unknown path implies all of its descendants. Past maxUnknownPaths
	// paths or maxUnknownPathSteps steps, Unknown is the whole value.
	Unknown []cty.Path
	// References are the addresses of the resources, data sources, ephemeral resources and
	// module calls the local depends on, directly, through other locals, or through the module
	// inputs behind the variables it uses: sorted, unique, qualified with the module address,
	// and with a statically known index kept ("aws_s3_bucket.b", "aws_subnet.a[0]",
	// "module.net.data.aws_ami.x", "module.m").
	References []string
	// ReferencesIncomplete reports that References may lack entries: this local or one it
	// depends on was too complex to analyse or is in a cycle, or the reference limit was hit.
	ReferencesIncomplete bool
	DeclRange            hcl.Range
}

// localState is a local while the dependency graph is built.
type localState struct {
	attr *hcl.Attribute
	file string
	// deps are the locals this one refers to that exist, sorted and unique; mods are the
	// module calls it refers to that exist, sorted and unique.
	deps, mods []string
	refs       []string
	// vars are the variables it refers to; roots are the other root names it uses (resource
	// types, data, module, path, ...), which evaluate as unknown.
	vars, roots []string
	// uses counts each use of "local.<name>" and "var.<name>"; otherUses counts the rest.
	uses      map[string]int
	otherUses int
	// safe: the expression passed safeToEvaluate, so its traversals were read.
	safe   bool
	cyclic bool
	// calls are the functions the expression calls, if it is safe.
	calls []functionCall
}

// EvaluateLocals evaluates the module's locals in dependency order, with vars as var.*. A local
// in a cycle is unknown with a warning; anything referring to resources, data sources or
// modules, and any expression that fails to evaluate, is unknown, never an error. Only a
// cancelled context is an error.
func (m *ParsedModule) EvaluateLocals(ctx context.Context, vars map[string]Variable) (map[string]Local, error) {
	locals, _, err := m.evaluateLocals(ctx, vars, nil, nil, nil)
	return locals, err
}

// DiagModuleCycle reports a module call whose inputs depend on its own outputs, through locals
// or other calls. Terraform rejects the module.
const DiagModuleCycle DiagCode = "module_cycle"

// callEvaluator evaluates module call c once its dependencies are evaluated, with locals and
// modules (module.<name> of the calls evaluated so far) as the caller's context, and returns
// module.<c.Name>.
type callEvaluator func(c *ModuleCall, locals map[string]Local, modules map[string]cty.Value) (cty.Value, error)

// evaluateLocals evaluates the module's locals and calls in one dependency order (T-0107i): a
// local can use module.<name> of a call, and a call's arguments can use locals and other calls.
// Each call is evaluated by evalCall when its turn comes. Locals and calls in a cycle are
// unknown with a warning (local_cycle, module_cycle); calls in a cycle are still evaluated, with
// the cycle's values unknown, but their outputs are unknown to the module. stop, when set, is
// asked before each local: once it reports true, the remaining locals are unknown (the tree
// budget is used up, ADR 0011). It returns the locals and module.<name> of every call.
func (m *ParsedModule) evaluateLocals(ctx context.Context, vars map[string]Variable, calls []*ModuleCall, evalCall callEvaluator, stop func() bool) (map[string]Local, map[string]cty.Value, error) {
	defer m.forgetInspections()
	states, order := m.declareLocals()
	byName := make(map[string]*ModuleCall, len(calls))
	for _, c := range calls {
		byName[c.Name] = c
	}
	for _, name := range order {
		s := states[name]
		calls, safe := m.inspectExpr(s.attr.Expr)
		if !safe {
			continue // evalExpr reports it; hcl must not parse its JSON templates
		}
		s.safe, s.calls = true, calls
		s.uses = map[string]int{}
		for _, tr := range s.attr.Expr.Variables() {
			switch root := tr.RootName(); root {
			case "local":
				if dep, ok := traversalAttr(tr, 1); ok {
					s.uses["local."+dep]++
					if _, exists := states[dep]; exists {
						s.deps = append(s.deps, dep)
					}
				}
			case "var":
				if name, ok := traversalAttr(tr, 1); ok {
					s.uses["var."+name]++
					s.vars = append(s.vars, name)
				}
			default:
				s.roots = append(s.roots, root)
				if ref, ok := referenceWithIndex(tr); ok {
					s.refs = append(s.refs, m.qualify(ref))
				}
				if name, ok := traversalAttr(tr, 1); ok && root == "module" && byName[name] != nil {
					s.uses["module."+name]++
					s.mods = append(s.mods, name)
					break
				}
				s.otherUses++
			}
		}
		slices.Sort(s.deps)
		s.deps = slices.Compact(s.deps)
		slices.Sort(s.mods)
		s.mods = slices.Compact(s.mods)
	}

	// The graph: a local is its name, a call is "module.<name>" (local names have no dots).
	deps := make(map[string][]string, len(states)+len(calls))
	nodes := slices.Clone(order)
	for _, name := range order {
		s := states[name]
		d := slices.Clone(s.deps)
		for _, mod := range s.mods {
			d = append(d, "module."+mod)
		}
		deps[name] = d
	}
	for _, c := range calls {
		key := "module." + c.Name
		nodes = append(nodes, key)
		deps[key] = m.callDependencies(c, states, byName)
	}

	b := &localsBudget{
		vars:      variablesObject(vars),
		sizes:     map[string]int{},
		varSizes:  map[string]int{},
		sensitive: map[string]bool{},
	}
	if evalCall != nil {
		b.modules = make(map[string]cty.Value, len(calls))
	}
	out := make(map[string]Local, len(states))
	refEntries, refsWarned, stopped := 0, false, false
	local := func(name string, cyclic bool) {
		s := states[name]
		s.cyclic = cyclic
		r := s.attr.NameRange
		l := Local{Name: name, DeclRange: s.attr.Range}
		var capped bool
		l.References, l.ReferencesIncomplete, capped = localReferences(s, out, vars, refEntries)
		refEntries += len(l.References)
		if capped && !refsWarned {
			refsWarned = true
			m.diag(SeverityWarning, DiagReferencesIncomplete, "Too many references through local values",
				fmt.Sprintf("From the local value %q on, locals past the reference limit record only their own references, not those of the locals they use.", name),
				s.file, r.Start.Line, r.Start.Column)
		}
		sensitive := s.safe && b.inputsSensitive(s)
		stopped = stopped || (!cyclic && stop != nil && stop())
		switch {
		case s.cyclic:
			l.Value = cty.DynamicVal
			if sensitive {
				// Fail closed, as for any unknown result with a sensitive input.
				l.Value = l.Value.Mark(SensitiveMark)
			}
			m.diag(SeverityWarning, DiagLocalCycle, "Cycle in local values",
				fmt.Sprintf("The local value %q depends on itself through other locals or module calls, so its value is unknown.", name),
				s.file, r.Start.Line, r.Start.Column)
		case stopped:
			// The tree's budget is used up; the instance is truncated and reported at its call.
			l.Value = cty.DynamicVal
			if sensitive {
				l.Value = l.Value.Mark(SensitiveMark)
			}
		default:
			l.Value = m.evalLocal(s, b, out, sensitive)
		}
		l.Unknown = unknownPaths(l.Value)
		m.usage.unknown += pathSteps(l.Unknown)
		b.sensitive["local."+name] = l.Value.ContainsMarked()
		out[name] = l
		m.usage.locals, m.usage.refs = b.total, refEntries
	}
	call := func(c *ModuleCall, cyclic bool) error {
		v, err := evalCall(c, out, b.modules)
		if err != nil {
			return err
		}
		if cyclic {
			r := c.DefRange
			m.diag(SeverityWarning, DiagModuleCycle, "Cycle through a module call",
				fmt.Sprintf("The inputs of the module call %q depend on its own outputs, so its outputs are unknown.", c.Name),
				c.File, r.Start.Line, r.Start.Column)
			v = cty.DynamicVal
		}
		b.modules[c.Name] = v
		return nil
	}
	for _, members := range dependencyComponents(nodes, deps) {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		cyclic := len(members) > 1 || slices.Contains(deps[members[0]], members[0])
		// In a cycle, every call member is unknown before any member is evaluated, so the
		// locals in it see unknown modules, not missing ones.
		var cycleCalls []*ModuleCall
		if cyclic {
			for _, key := range members {
				if name, isCall := strings.CutPrefix(key, "module."); isCall {
					b.modules[name] = cty.DynamicVal
					cycleCalls = append(cycleCalls, byName[name])
				}
			}
		}
		for _, key := range members {
			name, isCall := strings.CutPrefix(key, "module.")
			switch {
			case !isCall:
				local(name, cyclic)
			case !cyclic:
				if err := call(byName[name], false); err != nil {
					return nil, nil, err
				}
			}
		}
		for _, c := range cycleCalls {
			if err := call(c, true); err != nil {
				return nil, nil, err
			}
		}
	}
	m.sortDiagnostics()
	return out, b.modules, nil
}

// callDependencies returns the locals and calls that call c's arguments refer to, as graph keys.
// Arguments that are not safe to inspect add none; evaluating them reports them.
func (m *ParsedModule) callDependencies(c *ModuleCall, states map[string]*localState, calls map[string]*ModuleCall) []string {
	attrs, _ := c.Body.JustAttributes() // ModuleInputs reports these diagnostics
	var out []string
	for _, a := range sortedAttributes(attrs) {
		if _, safe := m.inspectExpr(a.Expr); !safe {
			continue
		}
		for _, tr := range a.Expr.Variables() {
			name, ok := traversalAttr(tr, 1)
			if !ok {
				continue
			}
			switch tr.RootName() {
			case "local":
				if _, exists := states[name]; exists {
					out = append(out, name)
				}
			case "module":
				if calls[name] != nil {
					out = append(out, "module."+name)
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// declareLocals collects the locals blocks' attributes, keeping the first of duplicates. order
// is the declaration order.
func (m *ParsedModule) declareLocals() (states map[string]*localState, order []string) {
	states = map[string]*localState{}
	for _, b := range m.Blocks {
		if b.Type != "locals" {
			continue
		}
		attrs, diags := b.Body.JustAttributes()
		m.addHCLDiags(b.File, diags)
		for _, attr := range sortedAttributes(attrs) {
			if _, dup := states[attr.Name]; dup {
				m.diag(SeverityError, DiagDuplicateLocal, "Duplicate local value definition",
					fmt.Sprintf("A local value named %q was already defined; this definition is ignored.", attr.Name),
					b.File, attr.NameRange.Start.Line, attr.NameRange.Start.Column)
				continue
			}
			states[attr.Name] = &localState{attr: attr, file: b.File}
			order = append(order, attr.Name)
		}
	}
	return states, order
}

// localReferences returns s's references: its own plus those of the locals and variables it
// uses (a variable's are those of the module input that set it), unless that would take the
// references stored so far (stored) past maxReferenceEntries. Then it returns only its own,
// which its source bounds, as incomplete, and capped is true.
func localReferences(s *localState, done map[string]Local, vars map[string]Variable, stored int) (refs []string, incomplete, capped bool) {
	incomplete = !s.safe || s.cyclic
	n := len(s.refs)
	for _, dep := range s.deps {
		n += len(done[dep].References)
		incomplete = incomplete || done[dep].ReferencesIncomplete
	}
	for _, name := range s.vars {
		n += len(vars[name].References)
		incomplete = incomplete || vars[name].ReferencesIncomplete
	}
	refs = slices.Clone(s.refs)
	if stored+n > maxReferenceEntries {
		incomplete, capped = true, true
	} else {
		for _, dep := range s.deps {
			refs = append(refs, done[dep].References...)
		}
		for _, name := range s.vars {
			refs = append(refs, vars[name].References...)
		}
	}
	slices.Sort(refs)
	return slices.Compact(refs), incomplete, capped
}

// inputsSensitive reports whether any local or variable s uses is, or contains, a sensitive
// value. Each value is checked once, so many locals using one large value stay cheap.
func (b *localsBudget) inputsSensitive(s *localState) bool {
	for _, dep := range s.deps {
		if b.sensitive["local."+dep] {
			return true
		}
	}
	for _, name := range s.mods {
		key := "module." + name
		marked, ok := b.sensitive[key]
		if !ok {
			marked = b.modules[name].ContainsMarked()
			b.sensitive[key] = marked
		}
		if marked {
			return true
		}
	}
	for _, name := range s.vars {
		key := "var." + name
		marked, ok := b.sensitive[key]
		if !ok {
			marked = b.vars.Type().HasAttribute(name) && b.vars.GetAttr(name).ContainsMarked()
			b.sensitive[key] = marked
		}
		if marked {
			return true
		}
	}
	return false
}

// localsBudget tracks the sizes of evaluated locals and variables against the limits.
type localsBudget struct {
	vars cty.Value
	// sizes are the evaluated locals' sizes; total is their sum.
	sizes    map[string]int
	varSizes map[string]int
	// sensitive caches whether "local.<name>" or "var.<name>" contains a sensitive value.
	sensitive map[string]bool
	total     int
	// totalWarned: a warning already says the locals together reached maxLocalsSize.
	totalWarned bool
	// modules holds module.<name> of the calls evaluated so far; nil when the module's calls
	// are not evaluated (EvaluateLocals), and module references are unknown.
	modules map[string]cty.Value
}

// estimate bounds the size of s's value from above before it is evaluated: its source plus
// every use of a local or variable at that value's full size. It stops counting past limit. It
// does not account for for expressions, which can repeat a value per element (T-0113).
func (b *localsBudget) estimate(s *localState, limit int) int {
	r := s.attr.Expr.Range()
	est := r.End.Byte - r.Start.Byte + s.otherUses
	for _, key := range slices.Sorted(maps.Keys(s.uses)) {
		est += s.uses[key] * b.size(key)
		if est > limit {
			break
		}
	}
	return est
}

// size is the size of "local.<name>", "module.<name>" or "var.<name>"; anything else counts as
// one.
func (b *localsBudget) size(key string) int {
	if name, ok := strings.CutPrefix(key, "local."); ok {
		return max(b.sizes[name], 1)
	}
	if name, ok := strings.CutPrefix(key, "module."); ok {
		if n, ok := b.varSizes[key]; ok {
			return n
		}
		n, ok := valueSize(b.modules[name], maxLocalValueSize, maxNesting)
		if !ok {
			n = maxLocalValueSize + 1
		}
		b.varSizes[key] = n // module values never change once set, and no variable has a dot
		return n
	}
	name, _ := strings.CutPrefix(key, "var.")
	if n, ok := b.varSizes[name]; ok {
		return n
	}
	n := 1
	if b.vars.Type().HasAttribute(name) {
		n, _ = valueSize(b.vars.GetAttr(name), maxLocalValueSize, maxNesting)
	}
	b.varSizes[name] = n
	return n
}

// evalLocal evaluates one local whose dependencies are already in done, within the size limits.
// Roots iace cannot resolve yet (resources, data sources, modules, path, terraform, ...) are
// unknown, so the parts of the value that do not depend on them stay known. sensitive reports
// whether an input is sensitive; an unknown result then stays sensitive (fail closed).
func (m *ParsedModule) evalLocal(s *localState, b *localsBudget, done map[string]Local, sensitive bool) cty.Value {
	unknown := cty.DynamicVal
	if sensitive {
		unknown = unknown.Mark(SensitiveMark)
	}
	// tooLarge reports a value over the limit for one local at that local, and the first value
	// that no longer fits in what remains of maxLocalsSize once for all.
	tooLarge := func(total bool) cty.Value {
		r := s.attr.NameRange
		switch {
		case !total:
			m.diag(SeverityWarning, DiagValueTooLarge, "Local value too large",
				fmt.Sprintf("The local value %q would pass the size or nesting limit for evaluated values, so its value is unknown.", s.attr.Name),
				s.file, r.Start.Line, r.Start.Column)
		case !b.totalWarned:
			b.totalWarned = true
			m.diag(SeverityWarning, DiagValueTooLarge, "Local values too large together",
				fmt.Sprintf("The local values reach the size limit for all locals together at %q: from there on, locals that do not fit are unknown.", s.attr.Name),
				s.file, r.Start.Line, r.Start.Column)
		}
		return unknown
	}
	remaining := maxLocalsSize - b.total
	ectx := &hcl.EvalContext{Variables: map[string]cty.Value{"var": b.vars}}
	if s.safe {
		if est := b.estimate(s, maxLocalValueSize); est > maxLocalValueSize {
			return tooLarge(false)
		} else if est > remaining {
			return tooLarge(true)
		}
		locals := make(map[string]cty.Value, len(s.deps))
		for _, dep := range s.deps {
			locals[dep] = done[dep].Value
		}
		ectx.Variables["local"] = cty.ObjectVal(locals)
		ectx.Functions = m.functions(s.attr.Expr, s.calls)
		for _, root := range s.roots {
			ectx.Variables[root] = cty.DynamicVal
		}
		if b.modules != nil && slices.Contains(s.roots, "module") {
			// Only the calls s uses: another name is an unsupported attribute, as in resources.
			mods := make(map[string]cty.Value, len(s.mods))
			for _, name := range s.mods {
				mods[name] = b.modules[name]
			}
			ectx.Variables["module"] = cty.ObjectVal(mods)
		}
		if slices.Contains(s.roots, "path") {
			ectx.Variables["path"] = m.pathObject()
		}
	}
	val, diags := m.evalExpr(s.attr.Expr, ectx)
	if diags.HasErrors() {
		// Report where evaluation failed, with hcl's Summary only: its Detail can quote values.
		summary := diags[0].Summary
		for _, d := range diags {
			if d.Severity == hcl.DiagError {
				summary = d.Summary
				break
			}
		}
		r := s.attr.Expr.Range()
		m.diag(SeverityWarning, DiagEvaluation, summary,
			"The expression could not be evaluated, so its value is unknown.",
			s.file, r.Start.Line, r.Start.Column)
		return unknown
	}
	size, ok := valueSize(val, maxLocalValueSize, maxNesting)
	if !ok {
		return tooLarge(false)
	}
	if size > remaining {
		return tooLarge(true)
	}
	b.sizes[s.attr.Name] = size
	b.total += size
	return val
}

// valueSize measures v: one unit per value plus one per string byte, map key or attribute name,
// and per decimal digit of a number's magnitude.
// It reports false as soon as the size passes limit or the nesting passes depth, and walks with
// an explicit stack that never holds more than limit values.
func valueSize(v cty.Value, limit, depth int) (int, bool) {
	type item struct {
		val   cty.Value
		depth int
	}
	size := 0
	stack := []item{{val: v}}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if it.depth > depth {
			return size, false
		}
		val, _ := it.val.Unmark()
		size++
		ty := val.Type()
		switch {
		case !val.IsKnown() || val.IsNull():
		case ty == cty.String:
			size += len(val.AsString())
		case ty == cty.Number:
			size += numberDigits(val)
		case ty.IsCollectionType() || ty.IsObjectType() || ty.IsTupleType():
			for elems := val.ElementIterator(); elems.Next(); {
				k, ev := elems.Element()
				// A set's keys are its elements, which may be unknown or marked.
				if k, _ := k.Unmark(); k.Type() == cty.String && k.IsKnown() && !k.IsNull() {
					size += len(k.AsString())
				}
				stack = append(stack, item{val: ev, depth: it.depth + 1})
				if size+len(stack) > limit {
					return size + len(stack), false
				}
			}
		}
		if size > limit {
			return size, false
		}
	}
	return size, true
}

// dependencyComponents returns the strongly connected components of the graph of nodes and
// deps, each after the components it depends on: a node in a component of more than one
// node, or that depends on itself, is in a cycle. It is Tarjan's algorithm with an explicit
// stack, so a long chain cannot exhaust the goroutine stack; nodes makes the result
// deterministic. Dependencies that are not nodes are ignored.
func dependencyComponents(nodes []string, deps map[string][]string) [][]string {
	type frame struct {
		name string
		next int
	}
	isNode := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		isNode[n] = true
	}
	// pos is a node's position in component while it is on that stack.
	index, low, pos := map[string]int{}, map[string]int{}, map[string]int{}
	var component []string
	var out [][]string
	var calls []frame
	visit := func(name string) {
		index[name], low[name] = len(index), len(index)
		pos[name] = len(component)
		component = append(component, name)
		calls = append(calls, frame{name: name})
	}
	for _, start := range nodes {
		if _, seen := index[start]; seen {
			continue
		}
		visit(start)
		for len(calls) > 0 {
			f := &calls[len(calls)-1]
			d := deps[f.name]
			if f.next < len(d) {
				dep := d[f.next]
				f.next++
				if !isNode[dep] {
					continue
				}
				if _, seen := index[dep]; !seen {
					visit(dep)
				} else if _, on := pos[dep]; on {
					low[f.name] = min(low[f.name], index[dep])
				}
				continue
			}
			name := f.name
			calls = calls[:len(calls)-1]
			if len(calls) > 0 {
				parent := calls[len(calls)-1].name
				low[parent] = min(low[parent], low[name])
			}
			if low[name] != index[name] {
				continue
			}
			members := slices.Clone(component[pos[name]:])
			component = component[:pos[name]]
			for _, mem := range members {
				delete(pos, mem)
			}
			out = append(out, members)
		}
	}
	return out
}

// variablesObject is var.* for evaluation.
func variablesObject(vars map[string]Variable) cty.Value {
	attrs := make(map[string]cty.Value, len(vars))
	for name, v := range vars {
		attrs[name] = v.Value
	}
	return cty.ObjectVal(attrs)
}

// traversalAttr returns the attribute name at step i of tr.
func traversalAttr(tr hcl.Traversal, i int) (string, bool) {
	if i >= len(tr) {
		return "", false
	}
	a, ok := tr[i].(hcl.TraverseAttr)
	return a.Name, ok
}

// referenceAddress returns the address of the resource, data source, ephemeral resource or
// module call that tr refers to, without instance keys.
func referenceAddress(tr hcl.Traversal) (string, bool) {
	root := tr.RootName()
	n := 2 // resource type and name, or module and call name
	switch root {
	case "var", "local", "path", "terraform", "count", "each", "self":
		return "", false
	case "data", "ephemeral":
		n = 3
	}
	parts := []string{root}
	for i := 1; i < n; i++ {
		name, ok := traversalAttr(tr, i)
		if !ok {
			return "", false
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, "."), true
}

// unknownPaths lists the outermost unknown paths in v, in value order, or only the whole value
// past maxUnknownPaths paths or maxUnknownPathSteps steps (fail closed). It walks with an
// explicit stack, so deep values cannot exhaust the goroutine stack, and links each node to its
// parent, so a path is built only when it is recorded.
func unknownPaths(v cty.Value) []cty.Path {
	type node struct {
		parent *node
		step   cty.PathStep
		depth  int
		val    cty.Value
	}
	var out []cty.Path
	steps := 0
	add := func(n *node) bool {
		steps += n.depth
		if len(out) >= maxUnknownPaths || steps > maxUnknownPathSteps {
			return false
		}
		p := make(cty.Path, n.depth)
		for c := n; c.parent != nil; c = c.parent {
			p[c.depth-1] = c.step
		}
		out = append(out, p)
		return true
	}
	stack := []*node{{val: v}}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		val, _ := n.val.Unmark()
		if !val.IsKnown() {
			if !add(n) {
				return []cty.Path{{}}
			}
			continue
		}
		ty := val.Type()
		container := ty.IsObjectType() || ty.IsMapType() || ty.IsListType() || ty.IsTupleType()
		if val.IsNull() || !container {
			// Sets have no stable element paths: an unknown element makes the set itself
			// not wholly known, which callers see through IsWhollyKnown.
			if ty.IsSetType() && !val.IsNull() && !val.IsWhollyKnown() && !add(n) {
				return []cty.Path{{}}
			}
			continue
		}
		first := len(stack)
		for elems := val.ElementIterator(); elems.Next(); {
			k, ev := elems.Element()
			var step cty.PathStep = cty.IndexStep{Key: k}
			if ty.IsObjectType() {
				step = cty.GetAttrStep{Name: k.AsString()}
			}
			stack = append(stack, &node{parent: n, step: step, depth: n.depth + 1, val: ev})
		}
		slices.Reverse(stack[first:])
	}
	return out
}

// numberDigits bounds the decimal digits cty writes for a known number: those of its magnitude
// (or its leading zeros, for a tiny one) plus those of its mantissa's precision, since a
// fraction such as 0.1 is held to 512 bits and formats to about 150 digits. cty formats,
// converts and compares numbers in decimal, at a cost that grows with the digits, while the
// binary value itself is cheap to build.
func numberDigits(v cty.Value) int {
	f := v.AsBigFloat()
	if f.IsInf() {
		return 0
	}
	exp := f.MantExp(nil)
	if exp < 0 {
		exp = -exp
	}
	return (exp + int(f.MinPrec())) * 30103 / 100000 // log10(2)
}
