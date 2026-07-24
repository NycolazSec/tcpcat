// internal/evasion/fragment.go
package evasion

import (
	"encoding/binary"
)

// FragmentPacket prend une trame brute (Ethernet + IP + TCP) et la découpe
// en plusieurs sous-trames selon le MTU (Maximum Transmission Unit) spécifié (ex: 8 octets).
func FragmentPacket(rawFrame []byte, mtu int) [][]byte {
	// Si la trame est trop petite ou si la fragmentation est désactivée (mtu = 0)
	if len(rawFrame) < 34 || mtu <= 0 {
		return [][]byte{rawFrame}
	}

	ethHeader := rawFrame[:14]
	ipHeaderBase := rawFrame[14:34]
	ipPayload := rawFrame[34:] // C'est l'en-tête TCP que l'on va découper

	var fragments [][]byte
	offset := 0

	for offset < len(ipPayload) {
		chunkSize := mtu
		if offset+chunkSize > len(ipPayload) {
			chunkSize = len(ipPayload) - offset
		}

		// Les fragments IP (sauf le dernier) doivent être des multiples de 8
		if chunkSize%8 != 0 && offset+chunkSize < len(ipPayload) {
			chunkSize = (chunkSize / 8) * 8
		}

		chunk := ipPayload[offset : offset+chunkSize]

		// Copie de l'en-tête IP original
		newIPHeader := make([]byte, 20)
		copy(newIPHeader, ipHeaderBase)

		// Mise à jour de la longueur totale (20 octets IP + taille du fragment)
		binary.BigEndian.PutUint16(newIPHeader[2:4], uint16(20+chunkSize))

		// Calcul de l'Offset et des drapeaux IP
		fragOffsetBlock := uint16(offset / 8)
		flagsAndOffset := fragOffsetBlock & 0x1FFF
		if offset+chunkSize < len(ipPayload) {
			flagsAndOffset |= 0x2000 // On active le drapeau MF (More Fragments)
		}
		binary.BigEndian.PutUint16(newIPHeader[6:8], flagsAndOffset)

		// Recalcul du Checksum de l'en-tête IP
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

// computeIPChecksum recalcule la validité mathématique de l'en-tête IP
func computeIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}