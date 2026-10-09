package terraform

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// Provider diagnostic codes.
const (
	// DiagInvalidProviderSource: a required_providers source is not a valid provider address,
	// so resources of that provider have no provider source.
	DiagInvalidProviderSource DiagCode = "invalid_provider_source"
	// DiagLockFileInvalid: .terraform.lock.hcl, or an entry in it, cannot be used, so the
	// versions it names are not known.
	DiagLockFileInvalid DiagCode = "lock_file_invalid"
)

// The provider lock file that `terraform init` writes next to a root module.
const (
	lockFile        = ".terraform.lock.hcl"
	maxLockFileSize = 1 << 20
	defaultRegistry = "registry.terraform.io"
)

// lockVersion matches an exact version as the lock file records it: MAJOR.MINOR.PATCH with an
// optional pre-release, which policies split to get the major version.
var lockVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// providerPart matches one part of a provider source address: a host name, namespace or type.
var providerPart = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// hostPart matches a registry host name, with an optional port.
var hostPart = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?$`)

// RequiredProvider is one entry of a module's required_providers.
type RequiredProvider struct {
	LocalName string
	// Source is the full source address ("registry.terraform.io/hashicorp/aws"), "" when the
	// declared source is not valid.
	Source string
	// Version is the version constraint, "" when absent or not a literal.
	Version   string
	DeclRange hcl.Range
}

// ProviderConfig is one provider block.
type ProviderConfig struct {
	LocalName, Alias string
	// Source is the provider's source address (providerSource), "" when unknown.
	Source          string
	File            string
	Range, DefRange hcl.Range
}

var requiredProvidersSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{{Type: "required_providers"}},
}

// RequiredProviders returns the module's required_providers entries by local name, read once
// from its terraform blocks without evaluation: the object form (`{source, version}`) and the
// legacy string form (a version constraint) are both accepted. A source is normalized to its
// full address (default host registry.terraform.io; a single name means namespace hashicorp);
// an invalid one is "" with an invalid_provider_source warning. The first declaration of a local
// name wins.
func (m *ParsedModule) RequiredProviders() map[string]RequiredProvider {
	if m.required != nil {
		return m.required
	}
	m.required = map[string]RequiredProvider{}
	for _, b := range m.Blocks {
		if b.Type != "terraform" {
			continue
		}
		content, _, _ := b.Body.PartialContent(requiredProvidersSchema)
		for _, rp := range content.Blocks {
			attrs, _ := rp.Body.JustAttributes()
			for _, a := range sortedAttributes(attrs) {
				if _, dup := m.required[a.Name]; dup {
					continue
				}
				m.required[a.Name] = m.requiredProvider(b.File, a)
			}
		}
	}
	return m.required
}

// requiredProvider reads one required_providers entry, without evaluating it.
func (m *ParsedModule) requiredProvider(file string, a *hcl.Attribute) RequiredProvider {
	isJSON := strings.HasSuffix(file, ".json")
	rp := RequiredProvider{LocalName: a.Name, Source: defaultSource(a.Name), DeclRange: a.Range}
	if v, ok := literalString(a.Expr, isJSON); ok {
		rp.Version = v // legacy form: a version constraint, default source
		return rp
	}
	invalid := func(r hcl.Range) RequiredProvider {
		rp.Source = ""
		m.diag(SeverityWarning, DiagInvalidProviderSource, "Invalid provider source",
			fmt.Sprintf("The source of provider %q is not a literal, valid provider address, so its resources have no provider source.", a.Name),
			r.Filename, r.Start.Line, r.Start.Column)
		return rp
	}
	items, diags := hcl.ExprMap(a.Expr)
	if diags.HasErrors() {
		return invalid(a.Expr.Range()) // neither a version string nor an object
	}
	for _, it := range items {
		keyExpr := it.Key
		if k, ok := keyExpr.(*hclsyntax.ObjectConsKeyExpr); ok {
			keyExpr = k.Wrapped // a quoted key ("source" = ...), which Terraform accepts
		}
		key, ok := literalString(keyExpr, isJSON)
		if !ok {
			key = hcl.ExprAsKeyword(it.Key)
		}
		val, literal := literalString(it.Value, isJSON)
		switch key {
		case "source":
			src, valid := normalizeSource(val)
			if !literal || !valid {
				return invalid(it.Value.Range())
			}
			rp.Source = src
		case "version":
			if literal {
				rp.Version = val
			}
		}
	}
	return rp
}

// defaultSource is Terraform's implied source for a local name: registry.terraform.io/hashicorp/<name>,
// or the built-in terraform.io/builtin/terraform for "terraform" (terraform_data,
// terraform_remote_state).
func defaultSource(local string) string {
	if local == "terraform" {
		return "terraform.io/builtin/terraform"
	}
	if !providerPart.MatchString(local) {
		return ""
	}
	return defaultRegistry + "/hashicorp/" + local
}

// normalizeSource returns the full, lowercase provider address for a source of the form
// [host/]namespace/type, and false when it is not one.
func normalizeSource(src string) (string, bool) {
	parts := strings.Split(strings.ToLower(src), "/")
	switch len(parts) {
	case 2:
		parts = append([]string{defaultRegistry}, parts...)
	case 3:
	default:
		return "", false
	}
	if !hostPart.MatchString(parts[0]) || !providerPart.MatchString(parts[1]) || !providerPart.MatchString(parts[2]) {
		return "", false
	}
	return strings.Join(parts, "/"), true
}

// providerSource returns the source address of the provider a resource or provider block of the
// module uses through local name local: its required_providers entry, else Terraform's default.
func (m *ParsedModule) providerSource(local string) string {
	if rp, ok := m.RequiredProviders()[local]; ok {
		return rp.Source
	}
	return defaultSource(local)
}

// resourceProviderName returns the local provider name of a resource: the provider
// meta-argument's root ("aws" in "aws.eu"), else the type's prefix before its first "_".
func resourceProviderName(r *Resource) string {
	if r.ProviderConfig != "" {
		name, _, _ := strings.Cut(r.ProviderConfig, ".")
		return name
	}
	name, _, _ := strings.Cut(r.Type, "_")
	return name
}

var providerBlockSchema = &hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "alias"}}}

// ProviderConfigs returns the module's provider blocks in block order, with their local name,
// literal alias and source. Their configuration values are not evaluated (T-0122).
func (m *ParsedModule) ProviderConfigs() []ProviderConfig {
	var out []ProviderConfig
	for _, b := range m.Blocks {
		if b.Type != "provider" || len(b.Labels) != 1 {
			continue
		}
		p := ProviderConfig{LocalName: b.Labels[0], Source: m.providerSource(b.Labels[0]), File: b.File, Range: b.Range, DefRange: b.DefRange}
		content, _, _ := b.Body.PartialContent(providerBlockSchema)
		if a, ok := content.Attributes["alias"]; ok {
			p.Alias, _ = literalString(a.Expr, strings.HasSuffix(b.File, ".json"))
		}
		out = append(out, p)
	}
	return out
}

var lockProviderSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{{Type: "provider", LabelNames: []string{"source"}}},
}

var lockVersionSchema = &hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "version"}}}

// ReadLockFile reads dir's .terraform.lock.hcl through the scan root, at most 1 MiB and checked
// by the nesting guard before parsing, into exact versions by provider source address. Nothing
// is evaluated: an entry counts only with a valid address label and a literal version. A missing
// file is no versions. A file that cannot be used, or an unusable or duplicate entry, is a
// lock_file_invalid warning (duplicates keep the first), and so is a lock file that is not a
// regular file or leaves the scan root. Versions must be exact (MAJOR.MINOR.PATCH[-pre]).
// Reading never fails the scan.
func ReadLockFile(root *fsutil.Root, dir string) (map[string]string, []Diagnostic) {
	name := path.Join(dir, lockFile)
	versions := map[string]string{}
	var diags []Diagnostic
	warn := func(summary string, r hcl.Range) {
		diags = append(diags, Diagnostic{
			Severity: SeverityWarning, Code: DiagLockFileInvalid, Summary: summary,
			Detail: "The provider lock file cannot be used here, so the versions it names are not known.",
			File:   name, Line: r.Start.Line, Column: r.Start.Column,
		})
	}
	data, err := root.ReadFile(name, maxLockFileSize)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return versions, nil
	case errors.Is(err, fsutil.ErrTooLarge):
		warn(fmt.Sprintf("Lock file larger than %d bytes", maxLockFileSize), hcl.Range{})
		return versions, diags
	case err != nil:
		// Not a regular file, or a symlink leaving the scan root: unusable, as discovery
		// treats such entries. A cancelled or failing filesystem shows up in other reads.
		warn("Lock file not readable", hcl.Range{})
		return versions, diags
	}
	if checkNesting(name, data) != nil {
		warn("Lock file nested too deeply", hcl.Range{})
		return versions, diags
	}
	file, hdiags := hclsyntax.ParseConfig(data, name, hcl.InitialPos)
	if hdiags.HasErrors() {
		warn("Lock file syntax error", hcl.Range{})
		return versions, diags
	}
	content, _, cdiags := file.Body.PartialContent(lockProviderSchema)
	for _, d := range cdiags {
		if d.Severity == hcl.DiagError {
			var at hcl.Range
			if d.Subject != nil {
				at = *d.Subject
			}
			warn("Malformed block in the lock file", at)
		}
	}
	for _, b := range content.Blocks {
		src, ok := normalizeSource(b.Labels[0])
		if !ok || strings.Count(b.Labels[0], "/") != 2 {
			warn("Invalid provider address in the lock file", b.DefRange)
			continue
		}
		attrs, _, adiags := b.Body.PartialContent(lockVersionSchema)
		if adiags.HasErrors() {
			warn("Malformed provider entry in the lock file", b.DefRange)
			continue
		}
		a, ok := attrs.Attributes["version"]
		var version string
		if ok {
			version, ok = literalString(a.Expr, false)
		}
		if !ok || !lockVersion.MatchString(version) {
			warn("Lock file entry without an exact literal version", b.DefRange)
			continue
		}
		if _, dup := versions[src]; dup {
			warn("Provider listed twice in the lock file", b.DefRange)
			continue
		}
		versions[src] = version
	}
	return versions, diags
}
