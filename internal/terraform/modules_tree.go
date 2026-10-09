package terraform

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"syscall"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// Module call diagnostic codes.
const (
	// DiagModuleUnresolved: a module call whose source iace cannot load (ModuleCall.Unresolved
	// says why), so the module is not checked.
	DiagModuleUnresolved DiagCode = "module_unresolved"
	// DiagDuplicateModule: two module calls share a name. Terraform rejects the module.
	DiagDuplicateModule DiagCode = "duplicate_module"
	// DiagInvalidModuleName: a module call's name is not an identifier. Terraform rejects the
	// module.
	DiagInvalidModuleName DiagCode = "invalid_module_name"
	// DiagModuleManifestInvalid: the root module's .terraform/modules/modules.json cannot be
	// used (malformed, too large, duplicate keys), so no remote module is resolved through it.
	DiagModuleManifestInvalid DiagCode = "module_manifest_invalid"
)

// The module manifest that `terraform init` writes in a trusted context: remote modules resolve
// only through it, and only to directories inside the scan root (T-0107d).
const (
	manifestFile       = ".terraform/modules/modules.json"
	maxManifestSize    = 1 << 20
	maxManifestEntries = 10_000
)

// Limits on the module call tree of one root module (ADR 0008). Terraform has no depth limit,
// but each level is another module to evaluate, and a fan-out of calls grows the tree
// exponentially with the depth, so the calls of a tree, resolved or not, are bounded too.
const (
	MaxModuleDepth = 32
	MaxModuleCalls = 1_000
)

// UnresolvedReason says why a module call was not resolved.
type UnresolvedReason string

// Unresolved reasons.
const (
	// UnresolvedRemote: a registry, git, http or other non-local source that no trusted module
	// manifest resolves (TreeOptions.TrustModuleManifest).
	UnresolvedRemote UnresolvedReason = "remote_source"
	// UnresolvedStaleManifest: the manifest entry for the call records another source, so its
	// directory may hold other code than the call names.
	UnresolvedStaleManifest UnresolvedReason = "stale_manifest"
	// UnresolvedSourceNotLiteral: source is not a literal string, which Terraform rejects too.
	UnresolvedSourceNotLiteral UnresolvedReason = "source_not_literal"
	// UnresolvedMissingSource: the call has no source, which Terraform rejects too.
	UnresolvedMissingSource UnresolvedReason = "missing_source"
	// UnresolvedOutsideRoot: a local source that leaves the scan root, lexically or through a
	// symlink, or that cannot be reached inside it for another reason (permissions, a loop).
	UnresolvedOutsideRoot UnresolvedReason = "outside_root"
	// UnresolvedNotFound: a local source that is not a directory.
	UnresolvedNotFound UnresolvedReason = "not_found"
	// UnresolvedSymlink: a local source through a symlink, which is not followed, as discovery
	// does not follow symlinked directories: otherwise a link to an ancestor would defeat cycle
	// detection and the parse cache, both keyed by path.
	UnresolvedSymlink UnresolvedReason = "symlinked_directory"
	// UnresolvedDepthLimit: the called module would be nested deeper than MaxModuleDepth.
	UnresolvedDepthLimit UnresolvedReason = "depth_limit"
	// UnresolvedCycle: the called directory is the caller's or one of its ancestors'.
	UnresolvedCycle UnresolvedReason = "cycle"
	// UnresolvedCallLimit: the tree already holds MaxModuleCalls calls. The first call past the
	// limit is the only one recorded: the calls after it are not walked (ModuleTree.Truncated).
	UnresolvedCallLimit UnresolvedReason = "call_limit"
)

// unresolvedDetail explains each reason in a diagnostic.
var unresolvedDetail = map[UnresolvedReason]string{
	UnresolvedRemote:           "The module source is not local and no trusted .terraform/modules/modules.json resolves it; iace does not download modules, so this module is not checked.",
	UnresolvedStaleManifest:    "The .terraform/modules/modules.json entry for this call records another source, or a form of it iace does not normalize (such as github.com shorthand), so this module is not checked.",
	UnresolvedSourceNotLiteral: "The module source is not a literal string, so this module is not checked.",
	UnresolvedMissingSource:    "The module call has no source, so no module is checked.",
	UnresolvedOutsideRoot:      "The module source leaves the scan root, so this module is not checked.",
	UnresolvedNotFound:         "The module source is not a directory inside the scan root, so no module is checked.",
	UnresolvedSymlink:          "The module source goes through a symlink, which iace does not follow, so this module is not checked.",
	UnresolvedDepthLimit:       fmt.Sprintf("The module would be nested more than %d levels deep, so it is not checked.", MaxModuleDepth),
	UnresolvedCycle:            "The module source calls a directory that is already being loaded (a cycle), so it is not loaded again.",
	UnresolvedCallLimit: fmt.Sprintf("The root module's tree already holds %d module calls, so neither this call nor any later one in the tree is checked.",
		MaxModuleCalls),
}

// ModuleTree is a root module with the modules it calls, recursively.
type ModuleTree struct {
	Root *ModuleNode
	// Skipped are the entries left out while listing called directories that discovery did not
	// walk (hidden ones), by path. Listing shares discovery's MaxFiles budget.
	Skipped []Skip
	// Truncated reports that the tree reached MaxModuleCalls: the call that would pass it is
	// unresolved (call_limit), and the module blocks after it were not walked.
	Truncated bool
}

// ModuleNode is one module in the tree: the root, or the module one call loads.
type ModuleNode struct {
	// Address is "" for the root, else the call's address ("module.a.module.b").
	Address string
	// Dir is the module directory, relative to the scan root.
	Dir string
	// Depth is 0 for the root and one more per call.
	Depth int
	// Module is the directory's parse. A directory called more than once is parsed once, and
	// its nodes share the parse, which they treat as read-only.
	Module *ParsedModule
	// Calls are the module's module blocks in block order, without duplicates.
	Calls []*ModuleCall
	// key is the module's key in the manifest: the call names from the root, dot-joined.
	key string
}

// ModuleCall is one module block.
type ModuleCall struct {
	Name string
	// Address is the caller's address followed by "module.<name>".
	Address string
	// Source and Version are the literal source and version strings, "" when absent or not a
	// literal.
	Source, Version string
	// Child is the called module, nil when unresolved; Unresolved says why, "" when resolved.
	Child      *ModuleNode
	Unresolved UnresolvedReason
	// Body is the block's body, which holds the module inputs and meta-arguments.
	Body hcl.Body
	// File is relative to the scan root; Range spans the block and DefRange is its header.
	File            string
	Range, DefRange hcl.Range
}

var moduleCallSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "source"}, {Name: "version"}},
}

// treeLoader builds one ModuleTree.
type treeLoader struct {
	root   *fsutil.Root
	limits Limits
	dirs   map[string]Dir
	parsed map[string]*parsedDir
	lister *walker
	// listFull records that listing reached the file limit: later directories list nothing.
	listFull bool
	// rootDir is the root module's directory; manifest maps its manifest's keys to entries,
	// nil without a usable manifest, and manifestErr says why one was not usable.
	rootDir     string
	manifest    map[string]manifestEntry
	manifestErr string
	calls       int
	full        bool
	loading     []string // the directories from the root to the node being loaded
}

// parsedDir is one directory's parse with its module calls, analyzed once for all its nodes.
type parsedDir struct {
	m     *ParsedModule
	specs []callSpec
}

// callSpec is what a module block says independently of where in the tree it is loaded.
type callSpec struct {
	b               Block
	source, version string
	// target is the resolved directory, or reason says why there is none.
	target string
	reason UnresolvedReason
	// where is the source expression's range, or the block header without one.
	where hcl.Range
}

// TreeOptions are trusted settings for loading a module tree. They come from the pipeline (CLI
// flags or environment), never from the scanned repository or its .iace.yaml.
type TreeOptions struct {
	// TrustModuleManifest resolves remote module sources through the root module's
	// .terraform/modules/modules.json. Only a pipeline that removed any committed .terraform and
	// ran `terraform init` in a trusted step may set it: the scanned repository can commit a
	// manifest and module copies of its own (ADR 0013).
	TrustModuleManifest bool
}

// LoadModuleTree parses the root module in dir, a directory of d, and the modules it calls,
// recursively, depth first in block order. Each call's literal source is resolved against
// the calling directory and must stay inside the scan root without passing through a symlink; a
// directory discovery did not walk (a hidden one) is listed with discovery's rules and within its
// file budget. Every call up to MaxModuleCalls stays in the tree: one that cannot be loaded is
// unresolved, with a module_unresolved warning on its caller. Each directory is parsed and its
// module blocks analyzed once, however many calls load it. Remote sources resolve only through
// the module manifest, and only when opts trusts it (ADR 0013). Nothing is evaluated. Problems in the
// files are diagnostics on the modules; a file or directory that can no longer be read, a root
// that d does not list, or a cancelled context is an error.
func LoadModuleTree(ctx context.Context, root *fsutil.Root, d *Discovery, dir string, limits Limits, opts TreeOptions) (*ModuleTree, error) {
	l := &treeLoader{
		root:   root,
		limits: limits,
		dirs:   map[string]Dir{},
		parsed: map[string]*parsedDir{},
		lister: &walker{root: root, limits: limits, count: d.Entries, files: map[string][]string{}},
		// Discovery already recorded where the budget ran out.
		listFull: slices.ContainsFunc(d.Skipped, func(s Skip) bool { return s.Reason == SkipFileLimit }),
	}
	for _, dd := range d.Dirs {
		l.dirs[dd.Path] = dd
	}
	if _, ok := l.dirs[dir]; !ok {
		return nil, fmt.Errorf("load module tree: %q is not a discovered directory", dir)
	}
	l.rootDir = dir
	if opts.TrustModuleManifest {
		l.manifest, l.manifestErr = readManifest(root, path.Join(dir, manifestFile))
	}
	node := &ModuleNode{Dir: dir}
	if err := l.load(ctx, node); err != nil {
		return nil, fmt.Errorf("load module tree: %w", err)
	}
	for _, p := range l.parsed {
		p.m.sortDiagnostics()
	}
	slices.SortFunc(l.lister.skipped, func(a, b Skip) int { return comparePaths(a.Path, b.Path) })
	return &ModuleTree{Root: node, Skipped: l.lister.skipped, Truncated: l.full}, nil
}

// load parses node's directory and loads its calls, until the tree is full.
func (l *treeLoader) load(ctx context.Context, node *ModuleNode) error {
	p, err := l.parse(ctx, node.Dir)
	if err != nil {
		return err
	}
	node.Module = p.m
	if node.Depth == 0 && l.manifestErr != "" {
		p.m.diag(SeverityWarning, DiagModuleManifestInvalid, "Module manifest not used",
			l.manifestErr+", so no remote module is resolved through it.", path.Join(l.rootDir, manifestFile), 0, 0)
	}
	l.loading = append(l.loading, node.Dir)
	defer func() { l.loading = l.loading[:len(l.loading)-1] }()

	for i := range p.specs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if l.full {
			return nil
		}
		s := &p.specs[i]
		call := &ModuleCall{
			Name: s.b.Labels[0], Address: "module." + s.b.Labels[0], Source: s.source, Version: s.version,
			Body: s.b.Body, File: s.b.File, Range: s.b.Range, DefRange: s.b.DefRange,
		}
		if node.Address != "" {
			call.Address = node.Address + "." + call.Address
		}
		node.Calls = append(node.Calls, call)
		if l.calls >= MaxModuleCalls {
			call.Unresolved = UnresolvedCallLimit
			l.full = true
			unresolved(p.m, s, call.Unresolved)
			return nil
		}
		l.calls++
		key := call.Name
		if node.key != "" {
			key = node.key + "." + call.Name
		}
		target, reason := s.target, s.reason
		if reason == UnresolvedRemote {
			target, reason = l.remote(key, s.source)
		}
		call.Unresolved = reason
		if reason != "" {
			if s.reason == UnresolvedRemote {
				unresolved(p.m, s, reason) // analyze reports the reasons that hold everywhere
			}
			continue
		}
		switch {
		case slices.Contains(l.loading, target):
			call.Unresolved = UnresolvedCycle
		case node.Depth+1 > MaxModuleDepth:
			call.Unresolved = UnresolvedDepthLimit
		}
		if call.Unresolved != "" {
			unresolved(p.m, s, call.Unresolved)
			continue
		}
		call.Child = &ModuleNode{Address: call.Address, Dir: target, Depth: node.Depth + 1, key: key}
		if err := l.load(ctx, call.Child); err != nil {
			return err
		}
	}
	return nil
}

// parse returns dir's parse, parsing it and analyzing its module blocks at its first call. A
// hidden directory, which discovery did not walk, is listed first; any other directory missing
// from discovery has no Terraform files it accepted, and its skips are already recorded.
func (l *treeLoader) parse(ctx context.Context, dir string) (*parsedDir, error) {
	if p, ok := l.parsed[dir]; ok {
		return p, nil
	}
	d, ok := l.dirs[dir]
	if !ok {
		d = Dir{Path: dir}
		if hiddenPath(dir) && !l.listFull {
			files, full, err := l.lister.list(ctx, dir)
			if err != nil {
				return nil, err
			}
			d.Files, l.listFull = files, full
		}
	}
	m, err := ParseModule(ctx, l.root, d, l.limits)
	if err != nil {
		return nil, err
	}
	p := &parsedDir{m: m, specs: l.analyze(m)}
	l.parsed[dir] = p
	return p, nil
}

// analyze reads a module's module blocks once: names, literal source and version, and where a
// local source leads. Invalid and duplicate names are errors and their blocks are left out; a
// source that cannot be resolved anywhere in the tree is reported here, once.
func (l *treeLoader) analyze(m *ParsedModule) []callSpec {
	var specs []callSpec
	names := map[string]bool{}
	for _, b := range m.Blocks {
		if b.Type != "module" || len(b.Labels) != 1 {
			continue
		}
		name := b.Labels[0]
		r := b.DefRange
		if !hclsyntax.ValidIdentifier(name) {
			m.diag(SeverityError, DiagInvalidModuleName, "Invalid module name",
				"A module name must start with a letter or underscore and contain only letters, digits, underscores and dashes.",
				b.File, r.Start.Line, r.Start.Column)
			continue
		}
		if names[name] {
			m.diag(SeverityError, DiagDuplicateModule, "Duplicate module call",
				fmt.Sprintf("A module call named %q was already declared in this module.", name),
				b.File, r.Start.Line, r.Start.Column)
			continue
		}
		names[name] = true
		s := callSpec{b: b, where: b.DefRange}
		isJSON := strings.HasSuffix(b.File, ".json")
		content, _, _ := b.Body.PartialContent(moduleCallSchema)
		if v, ok := content.Attributes["version"]; ok {
			s.version, _ = literalString(v.Expr, isJSON)
		}
		src, ok := content.Attributes["source"]
		switch {
		case !ok:
			s.reason = UnresolvedMissingSource
		default:
			s.where = src.Expr.Range()
			var literal bool
			if s.source, literal = literalString(src.Expr, isJSON); !literal {
				s.reason = UnresolvedSourceNotLiteral
				break
			}
			s.target, s.reason = localSource(l.root, m.Dir, s.source)
		}
		if s.reason != "" && s.reason != UnresolvedRemote {
			unresolved(m, &s, s.reason) // a remote source may resolve through the manifest
		}
		specs = append(specs, s)
	}
	return specs
}

// unresolved reports a call that is not loaded, at its source.
func unresolved(m *ParsedModule, s *callSpec, reason UnresolvedReason) {
	m.diag(SeverityWarning, DiagModuleUnresolved, "Module not resolved",
		fmt.Sprintf("%s (%s)", unresolvedDetail[reason], reason),
		s.b.File, s.where.Start.Line, s.where.Start.Column)
}

// hiddenPath reports whether a path has a component discovery does not walk into.
func hiddenPath(p string) bool {
	return slices.ContainsFunc(strings.Split(p, "/"), func(c string) bool { return strings.HasPrefix(c, ".") && c != "." })
}

// list returns the Terraform files of one directory, as the walk would accept them, without
// entering its subdirectories. Its entries count toward the walker's limit; full reports that
// the limit was reached, which the walker recorded as a skip.
func (w *walker) list(ctx context.Context, dir string) (files []string, full bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	entries, err := w.root.ReadDir(dir)
	if err != nil {
		return nil, false, err
	}
	for _, e := range entries {
		name := e.Name()
		rel := join(dir, name)
		switch {
		case e.IsDir():
		case e.Type()&fs.ModeSymlink != 0:
			err = w.symlink(rel, name)
		case isTerraformFile(name):
			var info fs.FileInfo
			if info, err = e.Info(); err != nil {
				return nil, false, fsutil.WrapPathError("stat", rel, err)
			}
			err = w.file(rel, dir, info)
		}
		if errors.Is(err, errFileLimit) {
			return w.files[dir], true, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
	return w.files[dir], false, nil
}

// localSource resolves a local module source ("./" or "../", either slash) against the calling
// directory. It returns the reason when src is not local, or when the directory is not usable
// (confinedDir).
func localSource(root *fsutil.Root, dir, src string) (string, UnresolvedReason) {
	src = strings.ReplaceAll(src, `\`, "/")
	if !strings.HasPrefix(src, "./") && !strings.HasPrefix(src, "../") {
		return "", UnresolvedRemote
	}
	return confinedDir(root, path.Join(dir, src))
}

// confinedDir checks a cleaned, root-relative target directory: it returns the reason when the
// target leaves the scan root, passes through a symlink, or is not a directory inside it. Each
// component is checked without following it, so no symlink is followed at all; os.Root's escape
// error is not exported, so any error other than a missing path counts as leaving the root.
func confinedDir(root *fsutil.Root, target string) (string, UnresolvedReason) {
	if target == ".." || strings.HasPrefix(target, "../") || strings.HasPrefix(target, "/") {
		return "", UnresolvedOutsideRoot
	}
	if target == "." {
		return target, ""
	}
	parts := strings.Split(target, "/")
	for i := range parts {
		info, err := root.Lstat(strings.Join(parts[:i+1], "/"))
		switch {
		case errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR):
			return "", UnresolvedNotFound
		case err != nil:
			return "", UnresolvedOutsideRoot
		case info.Mode()&fs.ModeSymlink != 0:
			return "", UnresolvedSymlink
		case !info.IsDir():
			return "", UnresolvedNotFound
		}
	}
	return target, ""
}
