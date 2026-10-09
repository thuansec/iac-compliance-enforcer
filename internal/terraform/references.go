package terraform

import (
	"math/big"
	"slices"
	"strconv"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// referenceWithIndex returns the address tr refers to, as referenceAddress, followed by the
// index right after it when that index is a literal number or string ("aws_subnet.a[0]",
// `aws_subnet.b["k"]`): the input document keeps statically known indexes.
func referenceWithIndex(tr hcl.Traversal) (string, bool) {
	addr, ok := referenceAddress(tr)
	if !ok {
		return "", false
	}
	n := 2
	if root := tr.RootName(); root == "data" || root == "ephemeral" {
		n = 3
	}
	if len(tr) <= n {
		return addr, true
	}
	ix, ok := tr[n].(hcl.TraverseIndex)
	if !ok || !ix.Key.IsKnown() || ix.Key.IsNull() {
		return addr, true
	}
	key, _ := ix.Key.Unmark()
	switch key.Type() {
	case cty.Number:
		if i, acc := key.AsBigFloat().Int64(); acc == big.Exact && i >= 0 {
			return addr + "[" + strconv.FormatInt(i, 10) + "]", true
		}
	case cty.String:
		return addr + "[" + quoteKey(key.AsString()) + "]", true
	}
	return addr, true
}

// qualify prefixes a module-local address with the instance's module address.
func (m *ParsedModule) qualify(addr string) string {
	if m.addrPrefix == "" {
		return addr
	}
	return m.addrPrefix + "." + addr
}

// refResult is the references of one expression.
type refResult struct {
	refs       []string
	incomplete bool
}

// references returns the addresses expr refers to, sorted and unique: its own resource, data
// source, ephemeral resource and module call references, qualified with the module address,
// and the references of the locals and variables it uses, which are already qualified.
// incomplete is true when the expression is not safe to inspect, a local or variable it uses
// has incomplete references, or it uses a dynamic block iterator (whose for_each references are
// not carried). Every call charges its entries to the module's reference budget
// (maxReferenceEntries), and an expression whose references would pass what is left is refused
// before they are built: no references, and incomplete. Results are memoized by source range,
// since they do not depend on the instance being decoded; the slices are shared, never changed.
func (d *resourceDecoder) references(expr hcl.Expression) (refs []string, incomplete bool) {
	r := expr.Range()
	key := sourceKey{r.Filename, r.Start.Byte, r.End.Byte}
	if res, ok := d.refMemo[key]; ok {
		if !d.chargeReferences(len(res.refs), expr) {
			return nil, true
		}
		return res.refs, res.incomplete
	}
	if *d.refEntries >= maxReferenceEntries {
		d.chargeReferences(1, expr) // warns
		return nil, true
	}
	if _, safe := d.m.inspectExpr(expr); !safe {
		return nil, true
	}
	traversals := expr.Variables()
	// An upper bound on the entries, before any list is built.
	n := 0
	for _, tr := range traversals {
		name, _ := traversalAttr(tr, 1)
		switch tr.RootName() {
		case "local":
			n += len(d.locals[name].References)
		case "var":
			n += len(d.varRefs[name])
		default:
			n++
		}
	}
	if *d.refEntries+n > maxReferenceEntries {
		d.chargeReferences(n, expr) // warns
		return nil, true
	}
	for _, tr := range traversals {
		root := tr.RootName()
		if _, ok := d.iters[root]; ok {
			incomplete = true
			continue
		}
		name, _ := traversalAttr(tr, 1)
		switch root {
		case "local":
			if l, ok := d.locals[name]; ok {
				refs = append(refs, l.References...)
				incomplete = incomplete || l.ReferencesIncomplete
			}
		case "var":
			refs = append(refs, d.varRefs[name]...)
			incomplete = incomplete || d.varIncomplete[name]
		default:
			if addr, ok := referenceWithIndex(tr); ok {
				refs = append(refs, d.m.qualify(addr))
			}
		}
	}
	slices.Sort(refs)
	refs = slices.Compact(refs)
	if d.refMemo == nil {
		d.refMemo = map[sourceKey]refResult{}
	}
	d.refMemo[key] = refResult{refs, incomplete}
	d.chargeReferences(len(refs), expr) // fits: len(refs) <= n
	return refs, incomplete
}

// recordReferences records the references of the attribute at path of r (references).
func (d *resourceDecoder) recordReferences(r *Resource, path string, expr hcl.Expression) {
	refs, incomplete := d.references(expr)
	r.ReferencesIncomplete = r.ReferencesIncomplete || incomplete
	if len(refs) == 0 {
		return
	}
	if r.References == nil {
		r.References = map[string][]string{}
	}
	r.References[path] = refs
}

// chargeReferences reserves n entries of the module's reference budget for resources, outputs
// or module inputs. A refusal is reported once for the module, at expr.
func (d *resourceDecoder) chargeReferences(n int, expr hcl.Expression) bool {
	if *d.refEntries+n > maxReferenceEntries {
		if !d.m.refsWarned {
			d.m.refsWarned = true
			r := expr.Range()
			d.m.diag(SeverityWarning, DiagReferencesIncomplete, "Too many references",
				"The module's attributes refer to more addresses than iace records: from here on, references are incomplete.",
				r.Filename, r.Start.Line, r.Start.Column)
		}
		return false
	}
	*d.refEntries += n
	return true
}

// dynamicReferences marks r's references incomplete for a dynamic block whose for_each refers to
// anything, or whose content is not decoded (expanded is false): neither the for_each's
// references nor skipped content are recorded.
func (d *resourceDecoder) dynamicReferences(r *Resource, forEach hcl.Expression, expanded bool) {
	if !expanded || forEach == nil {
		r.ReferencesIncomplete = true
		return
	}
	if _, safe := d.m.inspectExpr(forEach); !safe || len(forEach.Variables()) > 0 {
		r.ReferencesIncomplete = true
	}
}
