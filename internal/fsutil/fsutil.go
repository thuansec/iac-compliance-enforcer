// Package fsutil is the only way iace reads scanned content. It confines every access to a scan
// root with os.Root, so neither ".." nor a symlink can leave it, refuses anything that is not a
// regular file, and caps how much it reads. It does no other I/O and never writes.
package fsutil

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrTooLarge means a file is larger than the caller's limit.
var ErrTooLarge = errors.New("file exceeds the size limit")

// ErrNotRegular means a path is a directory, FIFO, device or other non-regular file.
var ErrNotRegular = errors.New("not a regular file")

// Root is an open scan root. Paths given to its methods are slash-separated and relative to it.
// Errors quote the path, which comes from the scanned repository. It is safe for concurrent use.
type Root struct {
	root *os.Root
}

// OpenRoot opens dir as a scan root.
func OpenRoot(dir string) (*Root, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open scan root: %w", err)
	}
	return &Root{root: r}, nil
}

// Close releases the root.
func (r *Root) Close() error {
	return r.root.Close()
}

// OpenRoot opens the directory name inside r as a root of its own, so that neither ".." nor a
// symlink can leave that directory. The caller closes it.
func (r *Root) OpenRoot(name string) (*Root, error) {
	sub, err := r.root.OpenRoot(filepath.FromSlash(name))
	if err != nil {
		return nil, WrapPathError("open directory", name, err)
	}
	return &Root{root: sub}, nil
}

// ReadDir lists a directory in name order. Entry types are not followed through symlinks.
func (r *Root) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(r.root.FS(), name)
	if err != nil {
		return nil, WrapPathError("read directory", name, err)
	}
	return entries, nil
}

// Stat describes name, following symlinks only while they stay inside the root.
func (r *Root) Stat(name string) (fs.FileInfo, error) {
	fi, err := r.root.Stat(filepath.FromSlash(name))
	if err != nil {
		return nil, WrapPathError("stat", name, err)
	}
	return fi, nil
}

// Lstat describes name without following a final symlink. Symlinks in its parent directories
// are followed only while they stay inside the root.
func (r *Root) Lstat(name string) (fs.FileInfo, error) {
	fi, err := r.root.Lstat(filepath.FromSlash(name))
	if err != nil {
		return nil, WrapPathError("lstat", name, err)
	}
	return fi, nil
}

// ReadFile reads a regular file of at most limit bytes. Symlinks are followed only inside the
// root. The file is opened without blocking and checked on the open handle, so a FIFO or device
// swapped in after a Stat can neither hang the scan nor be read.
func (r *Root) ReadFile(name string, limit int64) ([]byte, error) {
	f, err := r.root.OpenFile(filepath.FromSlash(name), os.O_RDONLY|openNonBlock, 0)
	if err != nil {
		return nil, WrapPathError("read", name, err)
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing

	fi, err := f.Stat()
	if err != nil {
		return nil, WrapPathError("read", name, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("read %q: %w", name, ErrNotRegular)
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("read %q: %w (%d bytes, limit %d)", name, ErrTooLarge, fi.Size(), limit)
	}
	// The file may grow after Stat: read one byte past the limit to notice.
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, WrapPathError("read", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("read %q: %w (limit %d)", name, ErrTooLarge, limit)
	}
	return data, nil
}

// WrapPathError returns "op "name": cause". The name is quoted, and an *fs.PathError is unwrapped
// to its cause first, because its message repeats the raw path: a newline in a scanned file name
// must never reach an error message (and with it, a log line or CI annotation). errors.Is still
// matches the cause.
func WrapPathError(op, name string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return fmt.Errorf("%s %q: %w", op, name, err)
}
