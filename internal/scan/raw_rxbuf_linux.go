//go:build linux

package scan

import "syscall"

// rawRxBufferBytes is the receive buffer asked for on the shared raw
// socket. A SYN scan gets one reply per probe, as fast as it sends them:
// at 25 000 probes/s the kernel's default buffer (~200 KiB, a few hundred
// small segments) overflows between two reads, and every reply dropped
// there is an open port reported as filtered.
const rawRxBufferBytes = 64 << 20

// tuneRawRxBuffer enlarges fd's receive buffer. SO_RCVBUFFORCE (root /
// CAP_NET_ADMIN, which a raw scan already has) ignores net.core.rmem_max;
// plain SO_RCVBUF is the fallback and is silently capped by it.
func tuneRawRxBuffer(fd int) {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, rawRxBufferBytes); err != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, rawRxBufferBytes)
	}
}

// rawTxBufferBytes is the send buffer of the shared send socket. Every probe
// now goes through that one socket, so its buffer bounds how many probes can
// wait in the kernel for the interface at once; with one socket per probe,
// each had a default buffer of its own.
const rawTxBufferBytes = 4 << 20

// tuneRawTxBuffer enlarges fd's send buffer, the same way as tuneRawRxBuffer.
func tuneRawTxBuffer(fd int) {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, rawTxBufferBytes); err != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, rawTxBufferBytes)
	}
}
