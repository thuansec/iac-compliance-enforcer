package engine

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// maxMessage bounds a violation's message, in characters.
const maxMessage = 500

// Findings decodes res, the violations Evaluate returned for doc, into findings sorted by
// severity (most severe first), rule ID, file, line and address. Decoding is strict: each
// violation must be an object with the address of a resource in doc, a non-empty message of at
// most 500 characters and an optional attribute_path of names and non-negative integers; other
// keys are ignored. Anything else is a *PolicyError naming the rule, which never quotes the
// violation (it may hold scanned values).
func (e *Engine) Findings(doc *model.InputDocument, res Result) ([]model.Finding, error) {
	byAddress := make(map[string]*model.Resource, len(doc.Resources))
	for i := range doc.Resources {
		byAddress[doc.Resources[i].Address] = &doc.Resources[i]
	}
	var out []model.Finding
	for _, id := range slices.Sorted(maps.Keys(res)) {
		r, ok := e.rules[id]
		if !ok {
			return nil, fmt.Errorf("engine: internal error: a result for rule %s, which is not loaded", id)
		}
		for i, v := range res[id] {
			f, msg := finding(r, doc, byAddress, v)
			if msg != "" {
				return nil, &PolicyError{File: r.File, RuleID: r.ID, Msg: fmt.Sprintf("violation %d of root module %q: %s", i+1, doc.Source.RootModule, msg)}
			}
			out = append(out, f)
		}
	}
	SortFindings(out)
	return out, nil
}

// SortFindings sorts findings by severity (most severe first), rule ID, file, line and address,
// then column, fingerprint and message, so the order is total and outputs are deterministic.
func SortFindings(findings []model.Finding) {
	slices.SortFunc(findings, func(a, b model.Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity.Rank(), a.Severity.Rank()),
			strings.Compare(a.RuleID, b.RuleID),
			strings.Compare(a.Location.File, b.Location.File),
			cmp.Compare(a.Location.StartLine, b.Location.StartLine),
			strings.Compare(a.Resource.Address, b.Resource.Address),
			cmp.Compare(a.Location.StartColumn, b.Location.StartColumn),
			strings.Compare(a.Fingerprint, b.Fingerprint),
			strings.Compare(a.Message, b.Message),
		)
	})
}

// finding builds the finding of one violation, or returns why the violation is malformed.
func finding(r Rule, doc *model.InputDocument, byAddress map[string]*model.Resource, v any) (model.Finding, string) {
	obj, ok := v.(map[string]any)
	if !ok {
		return model.Finding{}, "a violation must be an object"
	}
	addr, ok := obj["address"].(string)
	if !ok {
		return model.Finding{}, "address is missing or not a string"
	}
	res, ok := byAddress[addr]
	if !ok {
		return model.Finding{}, "address is not a resource of the input document"
	}
	msg, ok := obj["message"].(string)
	switch {
	case !ok:
		return model.Finding{}, "message is missing or not a string"
	case strings.TrimSpace(msg) == "":
		return model.Finding{}, "message is empty"
	case utf8.RuneCountInString(msg) > maxMessage:
		return model.Finding{}, fmt.Sprintf("message is longer than %d characters", maxMessage)
	}
	var path model.Path
	if raw, present := obj["attribute_path"]; present && raw != nil {
		var why string
		if path, why = attributePath(raw); why != "" {
			return model.Finding{}, why
		}
		if len(path) == 0 {
			// [] names no attribute, as an absent path does: one fingerprint for both.
			path = nil
		}
	}
	refs := make([]string, len(r.RelatedResources))
	for i, rr := range r.RelatedResources {
		refs[i] = rr.Ref
	}
	frameworks := make(map[string][]string, len(r.Frameworks))
	for k, ctrls := range r.Frameworks {
		frameworks[k] = slices.Clone(ctrls)
	}
	return model.Finding{
		RuleID:   r.ID,
		Title:    r.Title,
		Severity: model.Severity(r.Severity),
		CSP:      r.CSP,
		Service:  r.Service,
		Status:   model.StatusOpen,
		Message:  msg,
		Resource: model.FindingResource{
			Address: res.Address, Type: res.Type, Module: res.Module, Provider: res.Provider,
		},
		RootModule:    doc.Source.RootModule,
		Location:      locate(res.Source, path),
		AttributePath: path,
		Remediation:   r.Remediation,
		Frameworks:    frameworks,
		References:    refs,
		Fingerprint:   model.Fingerprint(r.ID, doc.Source.RootModule, res.Address, path),
	}, ""
}

// attributePath decodes a violation's attribute_path: names and non-negative integers (OPA
// returns numbers as json.Number).
func attributePath(raw any) (model.Path, string) {
	list, ok := raw.([]any)
	if !ok {
		return nil, "attribute_path is not an array"
	}
	path := make(model.Path, 0, len(list))
	for i, el := range list {
		switch x := el.(type) {
		case string:
			if x == "" {
				return nil, fmt.Sprintf("attribute_path element %d is an empty name", i)
			}
			path = append(path, model.AttrStep(x))
		case json.Number:
			n, err := x.Int64()
			if err != nil || n < 0 || n > int64(^uint32(0)>>1) {
				return nil, fmt.Sprintf("attribute_path element %d is not a non-negative integer", i)
			}
			path = append(path, model.IndexStep(int(n)))
		default:
			return nil, fmt.Sprintf("attribute_path element %d is neither a name nor an index", i)
		}
	}
	return path, ""
}

// locate returns the range of path's nearest located attribute (path itself or an ancestor),
// in the file that sets it (ADR 0048), or the block's range when none is located.
func locate(src model.ResourceSource, path model.Path) model.Location {
	for n := len(path); n > 0; n-- {
		key := path[:n].String()
		rng, ok := src.Attributes[key]
		if !ok {
			continue
		}
		file := src.File
		if f, isOther := src.AttributeFiles[key]; isOther {
			file = f
		}
		return location(file, rng)
	}
	return location(src.File, src.Range)
}

func location(file string, r model.Range) model.Location {
	return model.Location{File: file, StartLine: r.StartLine, StartColumn: r.StartColumn, EndLine: r.EndLine, EndColumn: r.EndColumn}
}
