//go:build !linux && !windows

package scan

import "syscall"

// tuneRawRxBuffer asks for a larger receive buffer on the shared raw socket
// (see the Linux version for why); the system's own limit caps it.
func tuneRawRxBuffer(fd int) {
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8<<20)
}

// tuneRawTxBuffer asks for a larger send buffer on the shared send socket
// (see the Linux version for why); the system's own limit caps it.
func tuneRawTxBuffer(fd int) {
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4<<20)
}
