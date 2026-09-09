package rawnet

import (
	"fmt"
	"net"
	"syscall"
)

type RawSocket struct {
	fd int
}

func NewRawSocket(protocol int) (*RawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, protocol)
	if err != nil {
		return nil, fmt.Errorf("failed to create Raw Socket (root privileges required): %w", err)
	}

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("unable to set IP_HDRINCL: %w", err)
	}

	return &RawSocket{fd: fd}, nil
}

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

func (s *RawSocket) Close() error {
	return syscall.Close(s.fd)
}
