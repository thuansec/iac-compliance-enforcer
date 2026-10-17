// Package redact removes secret values before anything leaves the process: from input documents
// that iace prints, and later from reports and AI prompts. It holds the one list of credential
// names and secret patterns every output shares.
package redact

import (
	"maps"
	"math"
	"regexp"
	"slices"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// Placeholder replaces every redacted string.
const Placeholder = "<redacted>"

// credentialName matches attribute and block names that hold credentials (the
// iace-ai-remediation skill's list).
var credentialName = regexp.MustCompile(`(?i)(password|secret|token|private|credential|connection_string|access_key|api_key|sas)`)

// secretPatterns match secrets by their form, wherever they appear in a string.
var secretPatterns = []*regexp.Regexp{
	// AWS access key IDs.
	regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b`),
	// PEM private keys of any kind.
	regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`),
	// JSON web tokens: a header and claims that are base64url JSON objects.
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`),
	// Azure storage and service bus connection strings.
	regexp.MustCompile(`(?i)(?:AccountKey|SharedAccessKey|SharedAccessSignature)=`),
	// Azure storage account keys: 88 base64 characters.
	regexp.MustCompile(`(?:^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{86}==(?:$|[^A-Za-z0-9+/=])`),
	// URLs with credentials in their user information (a module source with a token).
	regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`),
	// Azure shared access signatures in a URL query (sig is URL-encoded, so no long run).
	regexp.MustCompile(`(?i)[?&]sig=[^&\s]`),
	// Passwords in ADO.NET-style connection strings (Azure SQL, PostgreSQL, MySQL).
	regexp.MustCompile(`(?i)(?:^|;)\s*(?:password|pwd)\s*=\s*[^;\s]`),
}

// tokenChars splits a string into runs of the characters keys and tokens are made of.
var tokenChars = regexp.MustCompile(`[A-Za-z0-9+/=_-]{33,}`)

// IsCredentialName reports whether an attribute or block name suggests that its value is a
// credential.
func IsCredentialName(name string) bool { return credentialName.MatchString(name) }

// IsSecret reports whether s contains a secret by its form: a known key pattern, or a run of
// more than 32 key characters that looks random (highEntropy).
func IsSecret(s string) bool {
	for _, p := range secretPatterns {
		if p.MatchString(s) {
			return true
		}
	}
	for _, tok := range tokenChars.FindAllString(s, -1) {
		if highEntropy(tok) {
			return true
		}
	}
	return false
}

// highEntropy reports whether tok looks randomly generated: it mixes upper case, lower case and
// digits, and its Shannon entropy per character reaches 90% of what a random string of its length
// over a 64-symbol alphabet measures on average (log2(64) - 63/(2n ln 2), the Miller-Madow
// estimate: short samples measure less than the alphabet's 6 bits, since few characters repeat).
// A fixed cutoff missed a quarter of random 33-character keys, and one scaled by log2(n) flagged
// resource paths; this one follows the sample size both ways. Hex digests (one case) never
// qualify.
func highEntropy(tok string) bool {
	var upper, lower, digit bool
	counts := map[rune]int{}
	for _, r := range tok {
		counts[r]++
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	if !upper || !lower || !digit {
		return false
	}
	n := float64(len(tok))
	var bits float64
	for _, c := range counts {
		p := float64(c) / n
		bits -= p * math.Log2(p)
	}
	expected := math.Log2(64) - 63/(2*n*math.Ln2)
	return bits >= 0.9*expected
}

// Document returns a deep copy of doc in which every value that may be a secret is Placeholder:
// every non-null value at a sensitive path (contract rule 4: never printed), and every string
// under a credential-like name (IsCredentialName) or with a secret's form (IsSecret). It covers
// resource, provider and backend values and module call sources and versions. doc is never
// modified, and the walk is linear in the document's size. Map keys are not redacted (T-0132).
func Document(doc *model.InputDocument) *model.InputDocument {
	if doc == nil {
		return nil
	}
	out := *doc
	out.Terraform.RequiredProviders = maps.Clone(doc.Terraform.RequiredProviders)
	if b := doc.Terraform.Backend; b != nil {
		rb := *b
		rb.Values = values(b.Values, nil)
		rb.Unknown = clonePaths(b.Unknown)
		out.Terraform.Backend = &rb
	}
	out.ProviderVersions = maps.Clone(doc.ProviderVersions)
	out.Providers = make([]model.ProviderConfig, len(doc.Providers))
	for i, p := range doc.Providers {
		p.Values = values(p.Values, p.Sensitive)
		p.Unknown, p.Sensitive = clonePaths(p.Unknown), clonePaths(p.Sensitive)
		out.Providers[i] = p
	}
	out.Resources = make([]model.Resource, len(doc.Resources))
	for i, r := range doc.Resources {
		r.Values = values(r.Values, r.Sensitive)
		r.Unknown, r.Sensitive = clonePaths(r.Unknown), clonePaths(r.Sensitive)
		r.References = make(map[string][]string, len(doc.Resources[i].References))
		for k, targets := range doc.Resources[i].References {
			r.References[k] = slices.Clone(targets)
		}
		r.Meta.DependsOn = slices.Clone(r.Meta.DependsOn)
		r.Meta.Lifecycle.IgnoreChanges = slices.Clone(r.Meta.Lifecycle.IgnoreChanges)
		r.Source.Attributes = maps.Clone(r.Source.Attributes)
		if r.Source.ModuleCall != nil {
			mc := *r.Source.ModuleCall
			r.Source.ModuleCall = &mc
		}
		out.Resources[i] = r
	}
	out.Variables = slices.Clone(doc.Variables)
	out.Outputs = make([]model.Output, len(doc.Outputs))
	for i, o := range doc.Outputs {
		o.References = slices.Clone(o.References)
		out.Outputs[i] = o
	}
	out.CoverageGaps = slices.Clone(doc.CoverageGaps)
	out.ModuleCalls = make([]model.ModuleCall, len(doc.ModuleCalls))
	for i, c := range doc.ModuleCalls {
		if IsSecret(c.Source) {
			c.Source = Placeholder
		}
		if IsSecret(c.Version) {
			c.Version = Placeholder
		}
		out.ModuleCalls[i] = c
	}
	return &out
}

// clonePaths copies a list of paths; paths themselves are never modified, so they are shared.
func clonePaths(paths []model.Path) []model.Path { return slices.Clone(paths) }

// values returns a redacted deep copy of v; sensitive lists the paths whose values are hidden.
func values(v model.Values, sensitive []model.Path) model.Values {
	if v == nil {
		return nil
	}
	set := make(map[string]bool, len(sensitive))
	for _, p := range sensitive {
		set[p.String()] = true
	}
	w := walker{sensitive: set}
	out := make(model.Values, len(v))
	for name, item := range v {
		out[name] = w.value(name, item, set[name], IsCredentialName(name))
	}
	return out
}

// walker copies values, redacting what lies below a sensitive path or a credential-like name.
type walker struct {
	sensitive map[string]bool
}

// value copies v found at key (a dot-joined path, as model.Path.String writes it). sensitive
// reports that key or an ancestor is a sensitive path: every non-null value below it is hidden.
// credential reports a credential-like name on the way: strings below it are hidden, while
// numbers and booleans (a token lifetime, a flag) are kept. A nil collection stays nil, since
// null means unknown.
func (w walker) value(key string, v any, sensitive, credential bool) any {
	switch v := v.(type) {
	case nil:
		return nil
	case string:
		if sensitive || credential || IsSecret(v) {
			return Placeholder
		}
		return v
	case map[string]any:
		if v == nil {
			return v
		}
		out := make(map[string]any, len(v))
		for name, item := range v {
			k := key + "." + name
			out[name] = w.value(k, item, sensitive || w.sensitive[k], credential || IsCredentialName(name))
		}
		return out
	case []any:
		if v == nil {
			return v
		}
		out := make([]any, len(v))
		for i, item := range v {
			k := key + "." + itoa(i)
			out[i] = w.value(k, item, sensitive || w.sensitive[k], credential)
		}
		return out
	default:
		if sensitive {
			return Placeholder
		}
		return v
	}
}

// itoa formats a list index as model.Path.String does.
func itoa(i int) string { return model.Path{model.IndexStep(i)}.String() }
