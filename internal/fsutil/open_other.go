//go:build !unix

package fsutil

// openNonBlock is 0 where opening a named pipe or device through os.Root does not block on open.
const openNonBlock = 0
