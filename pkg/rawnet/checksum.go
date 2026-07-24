// pkg/rawnet/checksum.go
package rawnet

import (
	"bytes"
	"encoding/binary"
	"net"
)

// Checksum calculates the 16-bit Internet checksum (RFC 1071) over a byte buffer.
func Checksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	// Sum of 16-bit words (Big Endian)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Handle the residual odd byte if it exists
	if length%2 != 0 {
		sum += uint32(data[length-1]) << 8
	}

	// Fold 32-bit carry to 16-bit (1's Complement)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

// TCPChecksum calculates the valid TCP checksum by constructing the IPv4 pseudo-header (RFC 793).
func TCPChecksum(srcIP, dstIP net.IP, tcpHeader, payload []byte) uint16 {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return 0
	}

	tcpLength := uint16(len(tcpHeader) + len(payload))
	buf := new(bytes.Buffer)

	// --- IPv4 Pseudo-Header ---
	_ = binary.Write(buf, binary.BigEndian, src)
	_ = binary.Write(buf, binary.BigEndian, dst)
	_ = binary.Write(buf, binary.BigEndian, uint8(0))  // Reserved zero byte
	_ = binary.Write(buf, binary.BigEndian, uint8(6))  // IP Protocol for TCP = 6
	_ = binary.Write(buf, binary.BigEndian, tcpLength) // Total length of the TCP segment

	// --- TCP Segment ---
	buf.Write(tcpHeader)
	buf.Write(payload)

	return Checksum(buf.Bytes())
}