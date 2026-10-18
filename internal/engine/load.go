// Package engine loads iace's Rego policies, validates each rule's metadata and evaluates the rules
// against input documents with an embedded OPA. Every policy problem is a *PolicyError naming the
// file, so the scan fails closed (exit 2) instead of running without a rule.
package engine

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/open-policy-agent/opa/v1/ast"
)

// Origin says whose rules are loaded: built-in rules use the IACE- ID prefix, which external
// bundles may not.
type Origin int

const (
	// BuiltIn is the library embedded in the binary (policies.FS).
	BuiltIn Origin = iota
	// External is a policy bundle with its own ID prefix.
	External
)

// PolicyError is a broken policy: a parse or compile error, invalid rule metadata, or an error
// raised while evaluating it. RuleID is set when the error is in a rule's own file.
type PolicyError struct {
	File   string
	RuleID string
	Msg    string
}

func (e *PolicyError) Error() string {
	if e.RuleID != "" {
		return e.File + " (rule " + e.RuleID + "): " + e.Msg
	}
	return e.File + ": " + e.Msg
}

// Rule is a validated rule package and its metadata (iace-rego-policies' metadata schema).
type Rule struct {
	ID               string
	Title            string
	Description      string
	Severity         string
	CSP              string
	Service          string
	ResourceTypes    []string
	Remediation      string
	RelatedResources []RelatedResource
	Frameworks       map[string][]string
	Params           map[string]any
	Deprecated       bool
	ReplacedBy       string
	// Package is the rule's package path without data., File the module it is defined in.
	Package string
	File    string
}

// RelatedResource is a documentation link of a rule.
type RelatedResource struct {
	Ref         string
	Description string
}

// Library is a loaded policy set: every non-test module, keyed by file, and the rules among
// them sorted by file.
type Library struct {
	Modules map[string]*ast.Module
	Rules   []Rule
}

const (
	ruleNamespace = "iace.rules"
	rulePrefix    = ruleNamespace + "."
)

var (
	builtInID  = regexp.MustCompile(`^IACE-(AWS|AZURE|GEN)-[A-Z0-9]+-\d{3}$`)
	externalID = regexp.MustCompile(`^[A-Z][A-Z0-9]+-[A-Z0-9-]+$`)
	serviceRe  = regexp.MustCompile(`^[a-z0-9_]+$`)
	idCSP      = map[string]string{"AWS": "aws", "AZURE": "azure", "GEN": "generic"}
	severities = []string{"critical", "high", "medium", "low", "info"}
	csps       = []string{"aws", "azure", "generic"}
	customKeys = []string{
		"id", "severity", "csp", "service", "resource_types", "remediation",
		"frameworks", "params", "deprecated", "replaced_by",
	}
)

// Load parses every .rego file of fsys except *_test.rego, in lexical order, and validates the
// metadata of each rule package (iace.rules.<csp>.<service>.<rule>). The first problem is
// returned as a *PolicyError.
func Load(fsys fs.FS, origin Origin) (*Library, error) {
	lib := &Library{Modules: map[string]*ast.Module{}}
	ids := map[string]string{}
	pkgs := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return &PolicyError{File: name, Msg: err.Error()}
		}
		if d.IsDir() || path.Ext(name) != ".rego" || strings.HasSuffix(name, "_test.rego") {
			return nil
		}
		src, err := fs.ReadFile(fsys, name)
		if err != nil {
			return &PolicyError{File: name, Msg: err.Error()}
		}
		mod, err := ast.ParseModuleWithOpts(name, string(src), ast.ParserOptions{
			ProcessAnnotation: true,
			RegoVersion:       ast.RegoV1,
		})
		if err != nil {
			return &PolicyError{File: name, Msg: err.Error()}
		}
		lib.Modules[name] = mod
		pkg := strings.TrimPrefix(mod.Package.Path.String(), "data.")
		isRule := pkg == ruleNamespace || strings.HasPrefix(pkg, ruleNamespace+".")
		if err := checkRulePaths(mod, pkg, isRule); err != nil {
			return &PolicyError{File: name, Msg: err.Error()}
		}
		if !isRule {
			return nil
		}
		r, err := ruleOf(mod, pkg, origin)
		if err != nil {
			return &PolicyError{File: name, Msg: err.Error()}
		}
		r.File = name
		if prev, ok := pkgs[pkg]; ok {
			return &PolicyError{File: name, Msg: fmt.Sprintf("rule package %s is already defined by %s: one file per rule", pkg, prev)}
		}
		pkgs[pkg] = name
		if prev, ok := ids[r.ID]; ok {
			return &PolicyError{File: name, Msg: fmt.Sprintf("rule ID %s is already used by %s", r.ID, prev)}
		}
		ids[r.ID] = name
		lib.Rules = append(lib.Rules, r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(lib.Rules) == 0 {
		return nil, &PolicyError{File: ".", Msg: "the policy source defines no rule packages"}
	}
	return lib, nil
}

// checkRulePaths rejects rules that write into the rule namespace from outside a rule package
// (package iace with rules.aws.s3.x.deny), and deny rules a rule package defines anywhere but at
// its own root (sub.deny): the engine queries only <rule package>.deny, so either would be a
// control that never runs, or one without metadata.
func checkRulePaths(mod *ast.Module, pkg string, isRule bool) error {
	for _, rule := range mod.Rules {
		full := pkg
		for i, t := range rule.Head.Ref() {
			switch v := t.Value.(type) {
			case ast.Var:
				if i == 0 {
					full += "." + string(v)
				} else {
					full += ".*"
				}
			case ast.String:
				full += "." + string(v)
			default:
				full += ".*"
			}
		}
		inNamespace := full == ruleNamespace || strings.HasPrefix(full, ruleNamespace+".")
		if inNamespace && !isRule {
			return fmt.Errorf("rule %s is in %s but package %s is not a rule package", full, ruleNamespace, pkg)
		}
		if isRule && strings.HasSuffix(full, ".deny") && full != pkg+".deny" {
			return fmt.Errorf("rule %s: a rule package defines deny only at its root (%s.deny)", full, pkg)
		}
	}
	return nil
}

// ruleOf validates a rule module: its package path, its package-scoped METADATA and its deny set.
func ruleOf(mod *ast.Module, pkg string, origin Origin) (Rule, error) {
	segs := strings.Split(strings.TrimPrefix(pkg, rulePrefix), ".")
	if !strings.HasPrefix(pkg, rulePrefix) || len(segs) != 3 {
		return Rule{}, fmt.Errorf("package %s is not iace.rules.<csp>.<service>.<rule>", pkg)
	}
	if !definesDeny(mod) {
		return Rule{}, fmt.Errorf("package %s does not define the partial set rule deny (deny contains ... if)", pkg)
	}
	var a *ast.Annotations
	for _, x := range mod.Annotations {
		if x.Scope == "package" {
			a = x
		}
	}
	if a == nil {
		return Rule{}, fmt.Errorf("package %s has no package-scoped METADATA block", pkg)
	}
	r := Rule{Package: pkg, Title: a.Title, Description: a.Description}
	switch {
	case r.Title == "":
		return Rule{}, errors.New("METADATA title is required")
	case utf8.RuneCountInString(r.Title) > 80:
		return Rule{}, errors.New("METADATA title is longer than 80 characters")
	case strings.TrimSpace(r.Description) == "":
		return Rule{}, errors.New("METADATA description is required")
	case len(a.RelatedResources) == 0:
		return Rule{}, errors.New("METADATA related_resources needs at least one entry")
	}
	for _, rr := range a.RelatedResources {
		if rr.Ref.Scheme != "https" || rr.Ref.Host == "" {
			return Rule{}, fmt.Errorf("METADATA related_resources ref %q is not an https URL", rr.Ref.String())
		}
		r.RelatedResources = append(r.RelatedResources, RelatedResource{Ref: rr.Ref.String(), Description: rr.Description})
	}
	if a.Custom == nil {
		return Rule{}, errors.New("METADATA custom is required")
	}
	if err := decodeCustom(a.Custom, &r); err != nil {
		return Rule{}, err
	}
	return r, checkCustom(r, segs, origin)
}

func definesDeny(mod *ast.Module) bool {
	for _, rule := range mod.Rules {
		ref := rule.Head.Ref()
		if len(ref) == 1 && ref[0].Equal(ast.VarTerm("deny")) && rule.Head.RuleKind() == ast.MultiValue {
			return true
		}
	}
	return false
}

// decodeCustom copies custom's keys into r, rejecting unknown keys (except x_*) and wrong types.
func decodeCustom(custom map[string]any, r *Rule) error {
	keys := make([]string, 0, len(custom))
	for k := range custom {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if !slices.Contains(customKeys, k) && !strings.HasPrefix(k, "x_") {
			return fmt.Errorf("METADATA custom.%s is not a known key (extension keys start with x_)", k)
		}
	}
	var err error
	str := func(k string, dst *string) {
		if v, ok := custom[k]; ok && err == nil {
			if s, isStr := v.(string); isStr {
				*dst = s
			} else {
				err = fmt.Errorf("METADATA custom.%s must be a string", k)
			}
		}
	}
	str("id", &r.ID)
	str("severity", &r.Severity)
	str("csp", &r.CSP)
	str("service", &r.Service)
	str("remediation", &r.Remediation)
	str("replaced_by", &r.ReplacedBy)
	if err != nil {
		return err
	}
	if v, ok := custom["resource_types"]; ok {
		if r.ResourceTypes, ok = stringList(v); !ok {
			return errors.New("METADATA custom.resource_types must be a list of strings")
		}
	}
	if v, ok := custom["frameworks"]; ok {
		m, isMap := v.(map[string]any)
		if !isMap {
			return errors.New("METADATA custom.frameworks must map framework keys to lists of control IDs")
		}
		r.Frameworks = map[string][]string{}
		fks := make([]string, 0, len(m))
		for fk := range m {
			fks = append(fks, fk)
		}
		slices.Sort(fks)
		for _, fk := range fks {
			ctrls, isList := stringList(m[fk])
			if !isList || len(ctrls) == 0 {
				return fmt.Errorf("METADATA custom.frameworks.%s must be a non-empty list of control IDs", fk)
			}
			r.Frameworks[fk] = ctrls
		}
	}
	if v, ok := custom["params"]; ok {
		if r.Params, ok = v.(map[string]any); !ok {
			return errors.New("METADATA custom.params must be a JSON Schema object")
		}
	}
	if v, ok := custom["deprecated"]; ok {
		if r.Deprecated, ok = v.(bool); !ok {
			return errors.New("METADATA custom.deprecated must be a boolean")
		}
	}
	return nil
}

// stringList returns v as a list of non-empty strings.
func stringList(v any) ([]string, bool) {
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, isStr := e.(string)
		if !isStr || s == "" {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// checkCustom validates the decoded custom fields against the package segments (csp, service).
func checkCustom(r Rule, segs []string, origin Origin) error {
	switch {
	case r.ID == "":
		return errors.New("METADATA custom.id is required")
	case origin == BuiltIn && !builtInID.MatchString(r.ID):
		return fmt.Errorf("METADATA custom.id %q does not match IACE-<AWS|AZURE|GEN>-<SERVICE>-<NNN>", r.ID)
	case origin == External && (strings.HasPrefix(r.ID, "IACE-") || !externalID.MatchString(r.ID)):
		return fmt.Errorf("METADATA custom.id %q must use the bundle's own prefix, not IACE-", r.ID)
	case !slices.Contains(severities, r.Severity):
		return fmt.Errorf("METADATA custom.severity %q is not one of %s", r.Severity, strings.Join(severities, ", "))
	case !slices.Contains(csps, r.CSP):
		return fmt.Errorf("METADATA custom.csp %q is not one of %s", r.CSP, strings.Join(csps, ", "))
	case r.CSP != segs[0]:
		return fmt.Errorf("METADATA custom.csp %q does not match the package segment %q", r.CSP, segs[0])
	case !serviceRe.MatchString(r.Service) || r.Service != segs[1]:
		return fmt.Errorf("METADATA custom.service %q must be the lowercase package segment %q", r.Service, segs[1])
	case len(r.ResourceTypes) == 0:
		return errors.New("METADATA custom.resource_types needs at least one Terraform type")
	case strings.TrimSpace(r.Remediation) == "":
		return errors.New("METADATA custom.remediation is required")
	}
	if origin == BuiltIn {
		if csp := idCSP[strings.Split(r.ID, "-")[1]]; csp != r.CSP {
			return fmt.Errorf("METADATA custom.id %s names a different CSP than custom.csp %q", r.ID, r.CSP)
		}
	}
	return nil
}
