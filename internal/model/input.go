package model

// The input document v1 is the Go → Rego contract: one document per root module (HCL mode) or
// per plan file (plan mode), passed to OPA as `input`. Its shape is specified in the
// iace-architecture skill (references/input-document.md), in schemas/input.v1.json and in
// docs/adr/0004-define-the-input-document-v1-contract.md. Field order below is the JSON key order.

// InputSchemaVersion is the schema_version of every input document v1.
const InputSchemaVersion = "1"

// InputSchemaID is the $id of schemas/input.v1.json.
const InputSchemaID = "https://github.com/thuansec/iac-compliance-enforcer/schemas/input.v1.json"

// InputDocument is the normalized view of one root module or plan file.
type InputDocument struct {
	SchemaVersion string            `json:"schema_version"`
	Source        DocumentSource    `json:"source"`
	Terraform     TerraformSettings `json:"terraform"`
	// ProviderVersions maps a provider source address to the exact version from
	// .terraform.lock.hcl (HCL mode) or the plan.
	ProviderVersions map[string]string `json:"provider_versions"`
	Providers        []ProviderConfig  `json:"providers"`
	// Resources holds managed resources and data sources (see Resource.Mode).
	Resources    []Resource    `json:"resources"`
	ModuleCalls  []ModuleCall  `json:"module_calls"`
	Variables    []Variable    `json:"variables"`
	Outputs      []Output      `json:"outputs"`
	CoverageGaps []CoverageGap `json:"coverage_gaps"`
}

// SourceKind says how a document was produced.
type SourceKind string

// Source kinds.
const (
	SourceHCL  SourceKind = "hcl"
	SourcePlan SourceKind = "plan"
)

// DocumentSource says where a document came from. Paths are relative to the scan root.
type DocumentSource struct {
	Kind       SourceKind `json:"kind"`
	RootModule string     `json:"root_module"`
	// PlanFile is set in plan mode only.
	PlanFile string `json:"plan_file,omitempty"`
}

// TerraformSettings is the root module's terraform block.
type TerraformSettings struct {
	// RequiredVersion is "" when the configuration sets none.
	RequiredVersion string `json:"required_version"`
	// Backend is nil (JSON null) when the configuration declares none.
	Backend           *Backend                       `json:"backend"`
	RequiredProviders map[string]ProviderRequirement `json:"required_providers"`
}

// Backend is the root module's backend block.
type Backend struct {
	Type    string `json:"type"`
	Values  Values `json:"values"`
	Unknown []Path `json:"unknown"`
}

// ProviderRequirement is one entry of required_providers, keyed by local name.
type ProviderRequirement struct {
	Source  string `json:"source"`
	Version string `json:"version"`
}

// ProviderConfig is one provider block.
type ProviderConfig struct {
	LocalName   string         `json:"local_name"`
	Alias       string         `json:"alias"`
	Source      string         `json:"source"`
	Values      Values         `json:"values"`
	Unknown     []Path         `json:"unknown"`
	Sensitive   []Path         `json:"sensitive"`
	SourceRange SourceLocation `json:"source_range"`
}

// ResourceMode distinguishes managed resources from data sources.
type ResourceMode string

// Resource modes.
const (
	ModeManaged ResourceMode = "managed"
	ModeData    ResourceMode = "data"
)

// Resource is one resource or data source instance.
type Resource struct {
	// Address is the full instance address, unique within the document.
	Address string `json:"address"`
	// BaseAddress is Address without this resource's own instance key.
	BaseAddress string       `json:"base_address"`
	Mode        ResourceMode `json:"mode"`
	Type        string       `json:"type"`
	Name        string       `json:"name"`
	// Index is the instance key: NoKey without count/for_each, or when the key is unknown.
	Index InstanceKey `json:"index"`
	// Module is the module path, such as module.net, or "" for the root module.
	Module string `json:"module"`
	// Provider is the provider source address.
	Provider string `json:"provider"`
	// ProviderConfig is "aws.eu" when aliased and "" for the default configuration.
	ProviderConfig string `json:"provider_config"`
	// Values holds attribute values. Nested blocks are arrays of objects, except that in .tf.json
	// input a block written as one object stays an object (ADR 0006); unknown values are nil.
	Values Values `json:"values"`
	// Unknown lists the paths of unknown values; an unknown path covers all its descendants.
	Unknown []Path `json:"unknown"`
	// Sensitive lists paths that reporters never print and AI never receives.
	Sensitive []Path `json:"sensitive"`
	// References maps a dot-joined attribute path to the module-qualified addresses it refers to.
	References map[string][]string `json:"references"`
	Meta       ResourceMeta        `json:"meta"`
	Source     ResourceSource      `json:"source"`
}

// ResourceMeta holds the meta-arguments that policies may inspect.
type ResourceMeta struct {
	CountUnknown   bool      `json:"count_unknown"`
	ForEachUnknown bool      `json:"for_each_unknown"`
	DependsOn      []string  `json:"depends_on"`
	Lifecycle      Lifecycle `json:"lifecycle"`
}

// Lifecycle holds the lifecycle settings that are written in the configuration; absent settings
// are omitted, so an empty lifecycle block encodes as {}.
type Lifecycle struct {
	PreventDestroy *bool `json:"prevent_destroy,omitempty"`
	// IgnoreChanges holds dot-joined attribute paths; Terraform's `all` keyword is "*".
	IgnoreChanges []string `json:"ignore_changes,omitempty"`
}

// ResourceSource locates a resource in the scanned files.
type ResourceSource struct {
	File  string `json:"file"`
	Range Range  `json:"range"`
	// Attributes maps a dot-joined attribute path to the range of its expression.
	Attributes map[string]Range `json:"attributes"`
	// ModuleCall is the module block that instantiated this resource; nil in the root module.
	ModuleCall *SourceLocation `json:"module_call,omitempty"`
}

// SourceLocation is a range in a file relative to the scan root.
type SourceLocation struct {
	File  string `json:"file"`
	Range Range  `json:"range"`
}

// Range is a 1-based source range; columns count bytes.
type Range struct {
	StartLine   int `json:"start_line"`
	StartColumn int `json:"start_column"`
	EndLine     int `json:"end_line"`
	EndColumn   int `json:"end_column"`
}

// ModuleCall is one module block, used by module supply-chain rules.
type ModuleCall struct {
	Address  string `json:"address"`
	Source   string `json:"source"`
	Version  string `json:"version"`
	Resolved bool   `json:"resolved"`
	// Reason says why an unresolved module could not be loaded; "" when Resolved.
	Reason      string         `json:"reason"`
	SourceRange SourceLocation `json:"source_range"`
}

// Variable describes an input variable. It never carries a value: values are inlined where used.
type Variable struct {
	Name       string `json:"name"`
	Module     string `json:"module"`
	Sensitive  bool   `json:"sensitive"`
	HasDefault bool   `json:"has_default"`
	Type       string `json:"type"`
}

// Output describes an output value and the addresses it refers to.
type Output struct {
	Name        string         `json:"name"`
	Module      string         `json:"module"`
	Sensitive   bool           `json:"sensitive"`
	References  []string       `json:"references"`
	SourceRange SourceLocation `json:"source_range"`
}

// GapKind classifies a part of the configuration that iace could not check.
type GapKind string

// Coverage gap kinds.
const (
	GapParseError          GapKind = "parse_error"
	GapUnresolvedModule    GapKind = "unresolved_module"
	GapUnknownExpansion    GapKind = "unknown_expansion"
	GapLimitExceeded       GapKind = "limit_exceeded"
	GapUnsupportedFunction GapKind = "unsupported_function"
)

// CoverageGap records a part of the configuration that iace could not check, so it is reported
// instead of being treated as compliant.
type CoverageGap struct {
	Kind   GapKind `json:"kind"`
	Detail string  `json:"detail"`
	File   string  `json:"file"`
	Line   int     `json:"line"`
}
