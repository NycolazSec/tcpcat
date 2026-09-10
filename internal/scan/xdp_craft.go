package scan

import (
	"encoding/binary"
)

// xdpChecksum is the shared Internet checksum (RFC 1071) used both by the
// AF_XDP frame builders below and by the raw-socket TCP scanner on
// non-Linux platforms, so it stays cross-platform rather than moving into
// xdp_frames.go with the rest of this file's Linux-only frame crafting.
func xdpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
