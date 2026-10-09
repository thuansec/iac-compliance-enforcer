package terraform

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// manifestEntry is one module in .terraform/modules/modules.json.
type manifestEntry struct {
	Key     string `json:"Key"`
	Source  string `json:"Source"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
}

// windowsVolume matches a Windows drive or UNC prefix, which no root-relative Dir may have.
var windowsVolume = regexp.MustCompile(`^([A-Za-z]:|//)`)

// readManifest reads the manifest at name, through the root and within maxManifestSize, into
// its entries by key. A missing manifest is (nil, ""). One that cannot be used (unreadable,
// too large, not the expected JSON, trailing data, more than maxManifestEntries entries or a
// duplicate key) is (nil, why): its keys must never resolve modules ambiguously.
func readManifest(root *fsutil.Root, name string) (map[string]manifestEntry, string) {
	data, err := root.ReadFile(name, maxManifestSize)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, ""
	case errors.Is(err, fsutil.ErrTooLarge):
		return nil, fmt.Sprintf("The module manifest is larger than %d bytes", maxManifestSize)
	case err != nil:
		return nil, "The module manifest cannot be read"
	}
	var doc struct {
		Modules []manifestEntry `json:"Modules"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return nil, "The module manifest is not valid JSON of the expected form"
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, "The module manifest has data after its JSON value"
	}
	if len(doc.Modules) > maxManifestEntries {
		return nil, fmt.Sprintf("The module manifest has more than %d entries", maxManifestEntries)
	}
	out := make(map[string]manifestEntry, len(doc.Modules))
	for _, e := range doc.Modules {
		if _, dup := out[e.Key]; dup {
			return nil, "The module manifest lists a module key twice"
		}
		out[e.Key] = e
	}
	return out, ""
}

// remote resolves the remote source of the call with manifest key key through the manifest:
// the entry must record the same source (Terraform stores registry addresses with their host),
// and its Dir, relative to the root module's directory, must be a directory inside the scan
// root reached without symlinks (confinedDir).
func (l *treeLoader) remote(key, source string) (string, UnresolvedReason) {
	e, ok := l.manifest[key]
	if !ok {
		return "", UnresolvedRemote
	}
	if e.Source != source && e.Source != "registry.terraform.io/"+source {
		return "", UnresolvedStaleManifest
	}
	dir := strings.ReplaceAll(e.Dir, `\`, "/")
	if dir == "" || windowsVolume.MatchString(dir) || strings.HasPrefix(dir, "/") {
		return "", UnresolvedOutsideRoot
	}
	return confinedDir(l.root, path.Join(l.rootDir, dir))
}
