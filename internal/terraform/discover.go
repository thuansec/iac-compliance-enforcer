package terraform

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
)

// Limits bound how much of a scan root discovery accepts.
type Limits struct {
	// MaxFileSize is the largest Terraform file, in bytes, that is read.
	MaxFileSize int64
	// MaxFiles is the most entries discovery records in one scan root: Terraform files, accepted
	// or skipped, plus skipped symlinks. It bounds both the files read and the Skipped list.
	MaxFiles int
}

// DefaultLimits returns the documented limits: 1 MiB per file (ADR 0016: lexing and parsing a
// worst-case file holds about 110 times its size in memory) and 10,000 files.
func DefaultLimits() Limits {
	return Limits{MaxFileSize: 1 << 20, MaxFiles: 10_000}
}

// Dir is a directory that holds Terraform files.
type Dir struct {
	// Path is relative to the scan root and slash-separated; "." is the root itself.
	Path string
	// Files are the Terraform files in Path, relative to the scan root, in name order.
	Files []string
}

// SkipReason says why discovery left a path out.
type SkipReason string

// Skip reasons.
const (
	// SkipSymlinkEscape: a symlink whose target cannot be resolved inside the scan root (outside
	// it, absolute, missing or a loop). Its target may hold Terraform that is not scanned.
	SkipSymlinkEscape SkipReason = "symlink_escape"
	// SkipSymlinkDir: a symlinked directory inside the scan root, which is never followed (no
	// duplicates, no cycles).
	SkipSymlinkDir SkipReason = "symlinked_directory"
	// SkipNotRegular: a Terraform-named FIFO, device or socket.
	SkipNotRegular SkipReason = "not_regular"
	// SkipTooLarge: a Terraform file over Limits.MaxFileSize.
	SkipTooLarge SkipReason = "too_large"
	// SkipFileLimit: the first entry past Limits.MaxFiles; discovery stopped there.
	SkipFileLimit SkipReason = "file_limit"
)

// Skip is a path that discovery left out, so it can be reported as not checked.
type Skip struct {
	Path   string
	Reason SkipReason
	Detail string
}

// String returns a one-line message naming the path, the reason and the detail. The path comes
// from the scanned repository, so it is quoted: a newline in a file name cannot forge log lines.
func (s Skip) String() string {
	return fmt.Sprintf("%q: skipped (%s): %s", s.Path, s.Reason, s.Detail)
}

// Discovery is the result of walking a scan root.
type Discovery struct {
	// Dirs are the directories with at least one Terraform file, "." first, then by path.
	Dirs []Dir
	// Skipped are the paths left out, by path.
	Skipped []Skip
	// Entries is the number of entries counted toward Limits.MaxFiles, so module loading can
	// list more directories within the same budget.
	Entries int
}

// errFileLimit stops the walk once Limits.MaxFiles is reached.
var errFileLimit = errors.New("file limit reached")

// Discover walks the scan root and lists its Terraform files (*.tf and *.tf.json) per
// directory. It skips hidden directories (.terraform, .git and any other name starting with a
// dot) and the editor and hidden files Terraform itself ignores, and never follows a symlinked
// directory. It follows a symlinked Terraform file only to a regular file inside the root. Files
// over the size limit, special files, symlinked directories and symlinks that cannot be
// resolved inside the root are recorded in Skipped; past the entry limit the walk stops and
// records where. An unreadable directory or a cancelled context is an error, never a partial
// result.
func Discover(ctx context.Context, root *fsutil.Root, limits Limits) (*Discovery, error) {
	if limits.MaxFileSize <= 0 || limits.MaxFiles <= 0 {
		return nil, fmt.Errorf("discover: invalid limits %+v", limits)
	}
	w := &walker{root: root, limits: limits, files: map[string][]string{}}
	if err := w.walk(ctx, "."); err != nil && !errors.Is(err, errFileLimit) {
		return nil, fmt.Errorf("discover: %w", err)
	}

	d := &Discovery{Skipped: w.skipped, Entries: w.count}
	for dir, files := range w.files {
		d.Dirs = append(d.Dirs, Dir{Path: dir, Files: files})
	}
	slices.SortFunc(d.Dirs, func(a, b Dir) int { return comparePaths(a.Path, b.Path) })
	slices.SortFunc(d.Skipped, func(a, b Skip) int { return comparePaths(a.Path, b.Path) })
	return d, nil
}

type walker struct {
	root    *fsutil.Root
	limits  Limits
	count   int
	files   map[string][]string
	skipped []Skip
}

// walk visits dir's entries in name order, depth first, so the file-limit cut is deterministic.
func (w *walker) walk(ctx context.Context, dir string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := w.root.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		rel := join(dir, name)
		switch {
		case e.IsDir():
			if strings.HasPrefix(name, ".") {
				continue
			}
			if err := w.walk(ctx, rel); err != nil {
				return err
			}
		case e.Type()&fs.ModeSymlink != 0:
			if err := w.symlink(rel, name); err != nil {
				return err
			}
		case isTerraformFile(name):
			info, err := e.Info()
			if err != nil {
				return fsutil.WrapPathError("stat", rel, err)
			}
			if err := w.file(rel, dir, info); err != nil {
				return err
			}
		}
	}
	return nil
}

// symlink handles a symlink entry without ever walking through it. Hidden names are ignored
// like hidden files and directories.
func (w *walker) symlink(rel, name string) error {
	if strings.HasPrefix(name, ".") {
		return nil
	}
	info, inside := w.target(rel)
	switch {
	case !inside:
		return w.skip(rel, SkipSymlinkEscape,
			"the symlink target cannot be resolved inside the scan root (outside it, absolute, missing or a loop)")
	case info.IsDir():
		return w.skip(rel, SkipSymlinkDir, "symlinked directories are not followed")
	case isTerraformFile(name):
		return w.file(rel, parent(rel), info)
	default:
		return nil
	}
}

// target describes a symlink's target, and reports false when the target cannot be reached
// inside the root (it escapes, is absolute, is missing or loops). That is a skip, not an error.
func (w *walker) target(rel string) (fs.FileInfo, bool) {
	info, err := w.root.Stat(rel) // follows the link only while it stays inside the root
	if err != nil {
		return nil, false
	}
	return info, true
}

// file accepts a Terraform file, or records why it is skipped.
func (w *walker) file(rel, dir string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return w.skip(rel, SkipNotRegular, "not a regular file")
	}
	if info.Size() > w.limits.MaxFileSize {
		return w.skip(rel, SkipTooLarge, fmt.Sprintf("%d bytes, limit %d", info.Size(), w.limits.MaxFileSize))
	}
	if err := w.admit(rel); err != nil {
		return err
	}
	w.files[dir] = append(w.files[dir], rel)
	return nil
}

// skip records a skipped entry; it counts toward the entry limit like an accepted file.
func (w *walker) skip(rel string, reason SkipReason, detail string) error {
	if err := w.admit(rel); err != nil {
		return err
	}
	w.skipped = append(w.skipped, Skip{Path: rel, Reason: reason, Detail: detail})
	return nil
}

// admit counts one entry, or records the file-limit skip and stops the walk.
func (w *walker) admit(rel string) error {
	if w.count == w.limits.MaxFiles {
		w.skipped = append(w.skipped, Skip{Path: rel, Reason: SkipFileLimit, Detail: fmt.Sprintf(
			"more than %d Terraform files and skipped entries; this entry and the rest of the scan root were not discovered",
			w.limits.MaxFiles)})
		return errFileLimit
	}
	w.count++
	return nil
}

// isTerraformFile reports whether Terraform would load name as configuration: *.tf or *.tf.json,
// except hidden files and editor files (name~, #name#), which Terraform ignores too.
func isTerraformFile(name string) bool {
	if !strings.HasSuffix(name, ".tf") && !strings.HasSuffix(name, ".tf.json") {
		return false
	}
	ignored := strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") ||
		(strings.HasPrefix(name, "#") && strings.HasSuffix(name, "#"))
	return !ignored
}

func join(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}

func parent(rel string) string {
	i := strings.LastIndexByte(rel, '/')
	if i < 0 {
		return "."
	}
	return rel[:i]
}

// comparePaths orders "." first, then by path.
func comparePaths(a, b string) int {
	if a == b {
		return 0
	}
	if a == "." {
		return -1
	}
	if b == "." {
		return 1
	}
	return cmp.Compare(a, b)
}
