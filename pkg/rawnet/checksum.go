package rawnet

import (
	"bytes"
	"encoding/binary"
	"net"
)

func Checksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	if length%2 != 0 {
		sum += uint32(data[length-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

func TCPChecksum(srcIP, dstIP net.IP, tcpHeader, payload []byte) uint16 {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return 0
	}

	tcpLength := uint16(len(tcpHeader) + len(payload))
	buf := new(bytes.Buffer)

	_ = binary.Write(buf, binary.BigEndian, src)
	_ = binary.Write(buf, binary.BigEndian, dst)
	_ = binary.Write(buf, binary.BigEndian, uint8(0))
	_ = binary.Write(buf, binary.BigEndian, uint8(6))
	_ = binary.Write(buf, binary.BigEndian, tcpLength)

	buf.Write(tcpHeader)
	buf.Write(payload)

	return Checksum(buf.Bytes())
}
