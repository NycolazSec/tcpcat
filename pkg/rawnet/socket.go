// pkg/rawnet/socket.go
package rawnet

import (
	"fmt"
	"net"
	"syscall"
)

// RawSocket encapsulates an underlying raw socket from the operating system.
type RawSocket struct {
	fd int
}

// NewRawSocket initializes an IPv4 raw socket for a given protocol (e.g., syscall.IPPROTO_RAW or IPPROTO_TCP).
// Requires high execution privileges (root / sudo).
func NewRawSocket(protocol int) (*RawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, protocol)
	if err != nil {
		return nil, fmt.Errorf("failed to create Raw Socket (root privileges required): %w", err)
	}

	// IP_HDRINCL informs the kernel that the application provides the IP header itself
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("unable to set IP_HDRINCL: %w", err)
	}

	return &RawSocket{fd: fd}, nil
}

// SendPacket transmits a raw byte packet to the specified IPv4 address.
func (s *RawSocket) SendPacket(packet []byte, dstIP net.IP) error {
	dst := dstIP.To4()
	if dst == nil {
		return fmt.Errorf("invalid destination IP address")
	}

	var addr [4]byte
	copy(addr[:], dst)

	sockAddr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: addr,
	}

	return syscall.Sendto(s.fd, packet, 0, sockAddr)
}

// Close releases and closes the raw socket.
func (s *RawSocket) Close() error {
	return syscall.Close(s.fd)
}