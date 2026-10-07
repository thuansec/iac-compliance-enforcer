//go:build unix

package fsutil

import "syscall"

// openNonBlock keeps open(2) from blocking on a FIFO with no writer.
const openNonBlock = syscall.O_NONBLOCK
