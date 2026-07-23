// pkg/rawnet/socket.go
package rawnet

import (
	"fmt"
	"net"
	"syscall"
)

// RawSocket englobe un socket brut sous-jacent du système d'exploitation.
type RawSocket struct {
	fd int
}

// NewRawSocket initialise un socket brut IPv4 pour un protocole donné (ex: syscall.IPPROTO_RAW ou IPPROTO_TCP).
// Nécessite des privilèges d'exécution élevés (root / sudo).
func NewRawSocket(protocol int) (*RawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, protocol)
	if err != nil {
		return nil, fmt.Errorf("échec de la création du Raw Socket (privilèges root requis) : %w", err)
	}

	// IP_HDRINCL informe le noyau que l'application fournit elle-même l'en-tête IP
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("impossible de configurer IP_HDRINCL : %w", err)
	}

	return &RawSocket{fd: fd}, nil
}

// SendPacket transmet un paquet d'octets bruts à l'adresse IPv4 spécifiée.
func (s *RawSocket) SendPacket(packet []byte, dstIP net.IP) error {
	dst := dstIP.To4()
	if dst == nil {
		return fmt.Errorf("adresse IP de destination non valide")
	}

	var addr [4]byte
	copy(addr[:], dst)

	sockAddr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: addr,
	}

	return syscall.Sendto(s.fd, packet, 0, sockAddr)
}

// Close libère et ferme le socket brut.
func (s *RawSocket) Close() error {
	return syscall.Close(s.fd)
}