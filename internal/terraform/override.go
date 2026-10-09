package terraform

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// Override files (override.tf, *_override.tf and their .tf.json forms) are merged into the
// blocks they name, as Terraform merges them (ADR 0019), after every other file of the module is
// read. Override files apply in name order, and the blocks of one file in source order.
//   - variable, output, module and provider blocks (a provider by name and alias) merge into the
//     block they name: an attribute replaces the base attribute of the same name, and nested
//     blocks of a type replace all the base's nested blocks of that type. An override of a block
//     that does not exist is an error, as in Terraform.
//   - locals merge by name: each value replaces the base value of that name, which must exist.
//   - terraform settings merge into the module's settings: an attribute or nested block type
//     replaces the base's, except required_providers, which merges by provider name.
//   - Other blocks (resources and data sources among them) are not merged yet (T-0112b): each
//     is reported as override_not_merged and not used.

// inJSON reports whether expr was written in a .tf.json file. A merged block holds expressions
// from more than one file, so the syntax is decided by the expression's own file.
func inJSON(expr hcl.Expression) bool {
	return strings.HasSuffix(expr.Range().Filename, ".json")
}

// applyOverrides merges the blocks of the override files into m.Blocks. Override files are
// untrusted and may hold tens of thousands of blocks, so the work is linear in the blocks: each
// block's identity, local names and settings are read once, and each body is wrapped once, at
// the end.
func (m *ParsedModule) applyOverrides(ctx context.Context, overrides []Block) error {
	if len(overrides) == 0 {
		return nil
	}
	o := newOverrideMerger(m)
	for _, ov := range overrides {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch ov.Type {
		case "variable", "output", "module", "provider":
			o.block(ov)
		case "locals":
			o.locals(ov)
		case "terraform":
			o.settings(ov)
		default:
			m.diag(SeverityWarning, DiagOverrideNotMerged, "Override not merged",
				fmt.Sprintf("iace does not merge overrides of %s blocks yet, so the settings in this block are not checked.", ov.Type),
				ov.File, ov.DefRange.Start.Line, ov.DefRange.Start.Column)
		}
	}
	o.finish()
	return nil
}

// overrideMerger indexes the module's blocks once and records what each override changes.
type overrideMerger struct {
	m *ParsedModule
	// named maps a variable, output, module or provider block's type and identity to its index
	// (the first declaration); overs holds the override bodies for each, in order.
	named map[string]int
	overs map[int][]hcl.Body
	// localOwner maps a local name to the block that declares it now; settingOwners maps a
	// terraform setting (settingKey) to the blocks that set it now.
	localOwner    map[string]int
	settingOwners map[string][]int
	// duplicate holds the local names the module's own files declare twice. Terraform rejects
	// the duplicate before merging, so an override of one changes nothing and declareLocals
	// reports the duplicate where it is.
	duplicate map[string]bool
	// masks hides, in a locals or terraform block, what a later block replaced.
	masks map[int]*maskedBody
}

func newOverrideMerger(m *ParsedModule) *overrideMerger {
	o := &overrideMerger{
		m: m, named: map[string]int{}, overs: map[int][]hcl.Body{},
		localOwner: map[string]int{}, duplicate: map[string]bool{}, settingOwners: map[string][]int{}, masks: map[int]*maskedBody{},
	}
	for i, b := range m.Blocks {
		switch b.Type {
		case "variable", "output", "module", "provider":
			if key := b.Type + "\x00" + blockIdentity(b); !o.hasNamed(key) {
				o.named[key] = i
			}
		case "locals":
			attrs, _ := b.Body.JustAttributes()
			for name := range attrs {
				if _, ok := o.localOwner[name]; ok {
					o.duplicate[name] = true
				}
				o.localOwner[name] = i
			}
		case "terraform":
			for _, key := range settingKeys(b.Body) {
				o.settingOwners[key] = append(o.settingOwners[key], i)
			}
		}
	}
	return o
}

func (o *overrideMerger) hasNamed(key string) bool {
	_, ok := o.named[key]
	return ok
}

// block merges ov into the block of the same type and name (and alias, for a provider).
func (o *overrideMerger) block(ov Block) {
	id := blockIdentity(ov)
	i, ok := o.named[ov.Type+"\x00"+id]
	if !ok {
		name := strings.Join(ov.Labels, ".")
		if ov.Type == "provider" {
			name = strings.ReplaceAll(id, "\x00", ".")
		}
		o.m.diag(SeverityError, DiagOverrideWithoutBase, "Missing base declaration to override",
			fmt.Sprintf("There is no %s block named %q for this override to change.", ov.Type, name),
			ov.File, ov.DefRange.Start.Line, ov.DefRange.Start.Column)
		return
	}
	if ov.Type == "module" || ov.Type == "output" {
		content, _, _ := ov.Body.PartialContent(dependsOnSchema)
		if a, ok := content.Attributes["depends_on"]; ok {
			o.m.diag(SeverityError, DiagOverrideUnsupported, "Unsupported override",
				"The depends_on argument may not be overridden.",
				ov.File, a.NameRange.Start.Line, a.NameRange.Start.Column)
		}
	}
	o.overs[i] = append(o.overs[i], ov.Body)
}

var dependsOnSchema = &hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "depends_on"}}}

// blockIdentity is what an override names: the labels, and for a provider its alias too.
func blockIdentity(b Block) string {
	id := strings.Join(b.Labels, "\x00")
	if b.Type == "provider" {
		content, _, _ := b.Body.PartialContent(providerBlockSchema)
		if a, ok := content.Attributes["alias"]; ok {
			alias, _ := literalString(a.Expr, inJSON(a.Expr))
			id += "\x00" + alias
		}
	}
	return id
}

// locals replaces local values by name and adds the block after the module's blocks. A name no
// earlier block declares is an error and is dropped.
func (o *overrideMerger) locals(ov Block) {
	attrs, diags := ov.Body.JustAttributes()
	o.m.addHCLDiags(ov.File, diags)
	j := len(o.m.Blocks)
	kept := map[string]bool{}
	for _, a := range sortedAttributes(attrs) {
		owner, ok := o.localOwner[a.Name]
		if !ok {
			o.m.diag(SeverityError, DiagOverrideWithoutBase, "Missing base local value definition to override",
				fmt.Sprintf("There is no local value named %q for this override to change.", a.Name),
				ov.File, a.NameRange.Start.Line, a.NameRange.Start.Column)
			continue
		}
		if o.duplicate[a.Name] {
			continue
		}
		o.mask(owner).attrs[a.Name] = true
		o.localOwner[a.Name] = j
		kept[a.Name] = true
	}
	ov.Body = &onlyBody{inner: ov.Body, attrs: kept}
	o.m.Blocks = append(o.m.Blocks, ov)
}

// settings merges a terraform block into the module's settings: what it sets is hidden in the
// blocks that set it before, and the block is added after the module's blocks.
func (o *overrideMerger) settings(ov Block) {
	j := len(o.m.Blocks)
	for _, key := range settingKeys(ov.Body) {
		for _, owner := range o.settingOwners[key] {
			o.mask(owner).hide(key)
		}
		o.settingOwners[key] = []int{j}
	}
	o.m.Blocks = append(o.m.Blocks, ov)
}

// mask returns the mask of block i, creating it.
func (o *overrideMerger) mask(i int) *maskedBody {
	if o.masks[i] == nil {
		o.masks[i] = &maskedBody{attrs: map[string]bool{}, blocks: map[string]bool{}, keyed: map[string]map[string]bool{}}
	}
	return o.masks[i]
}

// finish wraps each changed body once.
func (o *overrideMerger) finish() {
	for i, overs := range o.overs {
		o.m.Blocks[i].Body = &mergedBody{base: o.m.Blocks[i].Body, overs: overs}
	}
	for i, mask := range o.masks {
		mask.inner = o.m.Blocks[i].Body
		o.m.Blocks[i].Body = mask
	}
}

// settingKeys lists what a terraform block sets: "attr:<name>", "block:<type>" (backend and
// cloud are one setting: a module has one or the other) and "required_providers:<name>".
func settingKeys(body hcl.Body) []string {
	content, _, _ := body.PartialContent(settingsSchema)
	var keys []string
	for name := range content.Attributes {
		keys = append(keys, "attr:"+name)
	}
	for _, blk := range content.Blocks {
		switch blk.Type {
		case "required_providers":
			attrs, _ := blk.Body.JustAttributes()
			for name := range attrs {
				keys = append(keys, "required_providers:"+name)
			}
		case "backend", "cloud":
			keys = append(keys, "block:backend")
		default:
			keys = append(keys, "block:"+blk.Type)
		}
	}
	return keys
}

// hide hides one setting (settingKeys) in the masked block.
func (b *maskedBody) hide(key string) {
	kind, name, _ := strings.Cut(key, ":")
	switch {
	case kind == "attr":
		b.attrs[name] = true
	case kind == "block" && name == "backend":
		b.blocks["backend"], b.blocks["cloud"] = true, true
	case kind == "block":
		b.blocks[name] = true
	default:
		if b.keyed[kind] == nil {
			b.keyed[kind] = map[string]bool{}
		}
		b.keyed[kind][name] = true
	}
}

// settingsSchema is what a terraform block may set, as Terraform reads it.
var settingsSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "required_version"}, {Name: "experiments"}, {Name: "language"}},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "required_providers"},
		{Type: "backend", LabelNames: []string{"type"}},
		{Type: "cloud"},
		{Type: "provider_meta", LabelNames: []string{"provider"}},
	},
}

// mergedBody is base with overs applied in order: an attribute of an override replaces the
// attribute of the same name, and an override's nested blocks of a type replace all the nested
// blocks of that type before it.
type mergedBody struct {
	base  hcl.Body
	overs []hcl.Body
}

func (b *mergedBody) Content(schema *hcl.BodySchema) (*hcl.BodyContent, hcl.Diagnostics) {
	optional := optionalSchema(schema)
	merged, diags := b.base.Content(optional)
	for _, over := range b.overs {
		content, overDiags := over.Content(optional)
		diags = append(diags, overDiags...)
		merged = mergeContent(merged, content)
	}
	return merged, append(diags, b.missing(schema, merged)...)
}

func (b *mergedBody) PartialContent(schema *hcl.BodySchema) (*hcl.BodyContent, hcl.Body, hcl.Diagnostics) {
	optional := optionalSchema(schema)
	merged, baseRemain, diags := b.base.PartialContent(optional)
	rest := &mergedBody{base: baseRemain}
	for _, over := range b.overs {
		content, remain, overDiags := over.PartialContent(optional)
		diags = append(diags, overDiags...)
		merged = mergeContent(merged, content)
		rest.overs = append(rest.overs, remain)
	}
	return merged, rest, append(diags, b.missing(schema, merged)...)
}

// missing reports the required attributes of schema that neither the base nor an override sets.
func (b *mergedBody) missing(schema *hcl.BodySchema, merged *hcl.BodyContent) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, a := range schema.Attributes {
		if _, ok := merged.Attributes[a.Name]; a.Required && !ok {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Missing required argument",
				Detail:   fmt.Sprintf("The argument %q is required, but no definition was found.", a.Name),
				Subject:  b.MissingItemRange().Ptr(),
			})
		}
	}
	return diags
}

func (b *mergedBody) JustAttributes() (hcl.Attributes, hcl.Diagnostics) {
	attrs, diags := b.base.JustAttributes()
	merged := make(hcl.Attributes, len(attrs))
	for name, a := range attrs {
		merged[name] = a
	}
	for _, over := range b.overs {
		attrs, overDiags := over.JustAttributes()
		diags = append(diags, overDiags...)
		for name, a := range attrs {
			merged[name] = a
		}
	}
	return merged, diags
}

func (b *mergedBody) MissingItemRange() hcl.Range { return b.base.MissingItemRange() }

// mergeContent applies over to base as mergedBody does.
func mergeContent(base, over *hcl.BodyContent) *hcl.BodyContent {
	out := &hcl.BodyContent{Attributes: hcl.Attributes{}, MissingItemRange: base.MissingItemRange}
	for name, a := range base.Attributes {
		out.Attributes[name] = a
	}
	for name, a := range over.Attributes {
		out.Attributes[name] = a
	}
	replaced := map[string]bool{}
	for _, blk := range over.Blocks {
		replaced[blk.Type] = true
	}
	for _, blk := range base.Blocks {
		if !replaced[blk.Type] {
			out.Blocks = append(out.Blocks, blk)
		}
	}
	out.Blocks = append(out.Blocks, over.Blocks...)
	return out
}

// optionalSchema is schema with no required attribute: an override sets only what it changes,
// and a base may leave to an override what it requires.
func optionalSchema(schema *hcl.BodySchema) *hcl.BodySchema {
	out := &hcl.BodySchema{Blocks: schema.Blocks}
	for _, a := range schema.Attributes {
		out.Attributes = append(out.Attributes, hcl.AttributeSchema{Name: a.Name})
	}
	return out
}

// maskedBody hides what a later override replaces: attributes by name, nested blocks by type,
// and, inside the nested blocks of a keyed type, attributes by name.
type maskedBody struct {
	inner  hcl.Body
	attrs  map[string]bool
	blocks map[string]bool
	keyed  map[string]map[string]bool
}

func (b *maskedBody) Content(schema *hcl.BodySchema) (*hcl.BodyContent, hcl.Diagnostics) {
	content, diags := b.inner.Content(optionalSchema(schema))
	return b.mask(content), diags
}

func (b *maskedBody) PartialContent(schema *hcl.BodySchema) (*hcl.BodyContent, hcl.Body, hcl.Diagnostics) {
	content, remain, diags := b.inner.PartialContent(optionalSchema(schema))
	rest := *b
	rest.inner = remain
	return b.mask(content), &rest, diags
}

func (b *maskedBody) JustAttributes() (hcl.Attributes, hcl.Diagnostics) {
	attrs, diags := b.inner.JustAttributes()
	out := make(hcl.Attributes, len(attrs))
	for name, a := range attrs {
		if !b.attrs[name] {
			out[name] = a
		}
	}
	return out, diags
}

func (b *maskedBody) MissingItemRange() hcl.Range { return b.inner.MissingItemRange() }

func (b *maskedBody) mask(content *hcl.BodyContent) *hcl.BodyContent {
	out := &hcl.BodyContent{Attributes: hcl.Attributes{}, MissingItemRange: content.MissingItemRange}
	for name, a := range content.Attributes {
		if !b.attrs[name] {
			out.Attributes[name] = a
		}
	}
	for _, blk := range content.Blocks {
		if b.blocks[blk.Type] {
			continue
		}
		if keys := b.keyed[blk.Type]; keys != nil {
			masked := *blk
			masked.Body = &maskedBody{inner: blk.Body, attrs: keys}
			blk = &masked
		}
		out.Blocks = append(out.Blocks, blk)
	}
	return out
}

// onlyBody keeps only the named attributes: an override's local values that have a base.
type onlyBody struct {
	inner hcl.Body
	attrs map[string]bool
}

func (b *onlyBody) Content(schema *hcl.BodySchema) (*hcl.BodyContent, hcl.Diagnostics) {
	content, diags := b.inner.Content(schema)
	return b.keep(content), diags
}

func (b *onlyBody) PartialContent(schema *hcl.BodySchema) (*hcl.BodyContent, hcl.Body, hcl.Diagnostics) {
	content, remain, diags := b.inner.PartialContent(schema)
	return b.keep(content), &onlyBody{inner: remain, attrs: b.attrs}, diags
}

func (b *onlyBody) JustAttributes() (hcl.Attributes, hcl.Diagnostics) {
	attrs, diags := b.inner.JustAttributes()
	out := make(hcl.Attributes, len(attrs))
	for name, a := range attrs {
		if b.attrs[name] {
			out[name] = a
		}
	}
	return out, diags
}

func (b *onlyBody) MissingItemRange() hcl.Range { return b.inner.MissingItemRange() }

func (b *onlyBody) keep(content *hcl.BodyContent) *hcl.BodyContent {
	out := *content
	out.Attributes = hcl.Attributes{}
	for name, a := range content.Attributes {
		if b.attrs[name] {
			out.Attributes[name] = a
		}
	}
	return &out
}
