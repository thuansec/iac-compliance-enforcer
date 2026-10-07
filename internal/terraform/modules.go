package terraform

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// Modules splits the discovered directories into root modules, which are scanned on their own,
// and local child modules, which are scanned only through the roots that call them.
type Modules struct {
	// Roots are the directories to scan as root modules, "." first, then by path.
	Roots []string
	// Children are the existing directories called through a local source, by path. They may
	// lie outside Discovery.Dirs, for example in a hidden directory.
	Children []string
}

var moduleSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{{Type: "module", LabelNames: []string{"name"}}},
}

var sourceSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "source"}},
}

// ClassifyModules reads the module blocks of every discovered file and splits the directories
// into roots and local children. A discovered directory that no other directory calls through a
// local source ("./" or "../") is a root. A call cycle that no root reaches would leave its
// directories unscanned, so its first directory by path is promoted to a root. Sources that are
// remote, not a literal string, or do not name a directory inside the scan root are ignored here;
// module resolution reports them. Syntax errors are not reported here either (parsing does), but
// the module blocks that still parse are used. A discovered file that can no longer be read is an
// error.
func ClassifyModules(ctx context.Context, root *fsutil.Root, d *Discovery, limits Limits) (*Modules, error) {
	calls := map[string][]string{} // caller directory → called directories, without self-calls
	called := map[string]bool{}
	for _, dir := range d.Dirs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, file := range dir.Files {
			data, err := root.ReadFile(file, limits.MaxFileSize)
			if err != nil {
				return nil, err
			}
			for _, src := range moduleSources(file, data) {
				target, ok := localTarget(root, dir.Path, src)
				if !ok || target == dir.Path {
					continue
				}
				calls[dir.Path] = append(calls[dir.Path], target)
				called[target] = true
			}
		}
	}

	m := &Modules{}
	isRoot := map[string]bool{}
	reached := map[string]bool{}
	var reach func(dir string)
	reach = func(dir string) {
		if reached[dir] {
			return
		}
		reached[dir] = true
		for _, t := range calls[dir] {
			reach(t)
		}
	}
	// d.Dirs is sorted, so both passes are deterministic.
	for _, dir := range d.Dirs {
		if !called[dir.Path] {
			m.Roots = append(m.Roots, dir.Path)
			isRoot[dir.Path] = true
			reach(dir.Path)
		}
	}
	for _, dir := range d.Dirs {
		if !reached[dir.Path] {
			m.Roots = append(m.Roots, dir.Path)
			isRoot[dir.Path] = true
			reach(dir.Path)
		}
	}
	for dir := range called {
		if !isRoot[dir] {
			m.Children = append(m.Children, dir)
		}
	}
	slices.SortFunc(m.Roots, comparePaths)
	slices.Sort(m.Children)
	return m, nil
}

// moduleSources returns the literal string sources of the module blocks in one file. A file
// nested too deeply to parse safely yields none; parsing reports it.
func moduleSources(name string, data []byte) []string {
	if checkNesting(name, data) != nil {
		return nil
	}
	isJSON := strings.HasSuffix(name, ".json")
	var file *hcl.File
	if isJSON {
		file, _ = hcljson.Parse(data, name)
	} else {
		file, _ = hclsyntax.ParseConfig(data, name, hcl.InitialPos)
	}
	if file == nil {
		return nil
	}
	content, _, _ := file.Body.PartialContent(moduleSchema)
	var sources []string
	for _, block := range content.Blocks {
		attrs, _, _ := block.Body.PartialContent(sourceSchema)
		attr, ok := attrs.Attributes["source"]
		if !ok {
			continue
		}
		if src, ok := literalString(attr.Expr, isJSON); ok {
			sources = append(sources, src)
		}
	}
	return sources
}

// literalString returns the value of a string literal without evaluating anything else:
// evaluating an untrusted expression (say "1+1+...+1") recurses without bound. Terraform itself
// requires a literal module source.
func literalString(expr hcl.Expression, isJSON bool) (string, bool) {
	if !isJSON {
		switch e := expr.(type) {
		case *hclsyntax.TemplateExpr:
			if !e.IsStringLiteral() {
				return "", false
			}
		case *hclsyntax.LiteralValueExpr:
		default:
			return "", false
		}
	}
	// A JSON expression with no evaluation context is its literal value, and the HCL
	// expressions above are literals, so Value only copies a constant.
	v, diags := expr.Value(nil)
	if diags.HasErrors() || v.IsNull() || !v.IsKnown() || !v.Type().Equals(cty.String) {
		return "", false
	}
	return v.AsString(), true
}

// localTarget resolves a local module source against the calling directory. It reports false
// for a non-local source, one that leaves the scan root, or one that is not a directory inside
// it (checked through the root, so a symlink cannot lead outside).
func localTarget(root *fsutil.Root, dir, src string) (string, bool) {
	src = strings.ReplaceAll(src, `\`, "/")
	if !strings.HasPrefix(src, "./") && !strings.HasPrefix(src, "../") {
		return "", false
	}
	target := path.Join(dir, src)
	if target == ".." || strings.HasPrefix(target, "../") {
		return "", false
	}
	info, err := root.Stat(target)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return target, true
}
