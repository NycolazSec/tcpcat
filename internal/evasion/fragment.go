// internal/evasion/fragment.go
package evasion

import (
	"encoding/binary"
)

func FragmentPacket(rawFrame []byte, mtu int) [][]byte {
	if len(rawFrame) < 34 || mtu <= 0 {
		return [][]byte{rawFrame}
	}

	ethHeader := rawFrame[:14]
	ipHeaderBase := rawFrame[14:34]
	ipPayload := rawFrame[34:]

	var fragments [][]byte
	offset := 0

	for offset < len(ipPayload) {
		chunkSize := mtu
		if offset+chunkSize > len(ipPayload) {
			chunkSize = len(ipPayload) - offset
		}

		if chunkSize%8 != 0 && offset+chunkSize < len(ipPayload) {
			chunkSize = (chunkSize / 8) * 8
		}

		chunk := ipPayload[offset : offset+chunkSize]

		newIPHeader := make([]byte, 20)
		copy(newIPHeader, ipHeaderBase)

		binary.BigEndian.PutUint16(newIPHeader[2:4], uint16(20+chunkSize))

		fragOffsetBlock := uint16(offset / 8)
		flagsAndOffset := fragOffsetBlock & 0x1FFF
		if offset+chunkSize < len(ipPayload) {
			flagsAndOffset |= 0x2000
		}
		binary.BigEndian.PutUint16(newIPHeader[6:8], flagsAndOffset)

		newIPHeader[10] = 0
		newIPHeader[11] = 0
		chk := computeIPChecksum(newIPHeader)
		binary.BigEndian.PutUint16(newIPHeader[10:12], chk)

		// Assemblage final du fragment
		frame := make([]byte, 0, 14+20+chunkSize)
		frame = append(frame, ethHeader...)
		frame = append(frame, newIPHeader...)
		frame = append(frame, chunk...)

		fragments = append(fragments, frame)
		offset += chunkSize
	}

	return fragments
}

func computeIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}
