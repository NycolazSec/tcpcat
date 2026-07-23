// pkg/rawnet/checksum.go
package rawnet

import (
	"bytes"
	"encoding/binary"
	"net"
)

// Checksum calcule la somme de contrôle Internet 16 bits (RFC 1071) sur un tampon d'octets.
func Checksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	// Somme des mots de 16 bits (Big Endian)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Gestion de l'octet impair résiduel s'il existe
	if length%2 != 0 {
		sum += uint32(data[length-1]) << 8
	}

	// Repliement du report 32 bits vers 16 bits (Complément à 1)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

// TCPChecksum calcule le checksum TCP valide en construisant le pseudo-header IPv4 (RFC 793).
func TCPChecksum(srcIP, dstIP net.IP, tcpHeader, payload []byte) uint16 {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return 0
	}

	tcpLength := uint16(len(tcpHeader) + len(payload))
	buf := new(bytes.Buffer)

	// --- Pseudo-Header IPv4 ---
	_ = binary.Write(buf, binary.BigEndian, src)
	_ = binary.Write(buf, binary.BigEndian, dst)
	_ = binary.Write(buf, binary.BigEndian, uint8(0))  // Octet réservé à zéro
	_ = binary.Write(buf, binary.BigEndian, uint8(6))  // Protocole IP pour TCP = 6
	_ = binary.Write(buf, binary.BigEndian, tcpLength) // Longueur totale du segment TCP

	// --- Segment TCP ---
	buf.Write(tcpHeader)
	buf.Write(payload)

	return Checksum(buf.Bytes())
}