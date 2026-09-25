//go:build linux

package netiface

import "golang.org/x/sys/unix"

// BindToDevice pins a socket to a specific network interface (SO_BINDTODEVICE),
// so traffic on it is sent/received strictly through that interface instead of
// whatever the kernel's routing table would otherwise pick -- the raw-socket
// equivalent of the AF_XDP engine's per-interface hook attachment. Requires
// CAP_NET_RAW (the same privilege raw sockets already need).
func BindToDevice(fd int, ifaceName string) error {
	return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifaceName)
}
