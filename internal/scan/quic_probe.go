package scan

import "encoding/binary"

// QUIC / HTTP/3 detection on UDP 443, the stateless way.
//
// Forging a fully valid QUIC Initial (a real TLS ClientHello with QUIC
// transport parameters, encrypted and header-protected with keys derived
// from the connection ID) is a lot of fragile crypto, and a single wrong
// byte makes the server silently drop the packet -- so it reads as "no
// QUIC" when there is. RFC 9000 gives a far more robust probe: a server
// MUST answer any long-header packet carrying a version it does not support
// with a Version Negotiation packet listing the versions it *does* support
// -- regardless of the rest of the payload. So we send a long-header packet
// stamped with a deliberately unsupported (GREASE) version, and any QUIC
// server answers with a Version Negotiation, which both proves QUIC/HTTP/3
// is there and enumerates its supported versions. A non-QUIC UDP service on
// 443 stays silent.

// quicGreaseVersion is a reserved "GREASE" QUIC version (pattern 0x?a?a?a?a,
// RFC 9000 §15): no server implements it, so every QUIC server is forced to
// reply with a Version Negotiation packet rather than continuing a handshake.
const quicGreaseVersion = 0x1a2a3a4a

// quicMinDatagram is the minimum size a client's first flight must reach
// (RFC 9000 §14.1); servers may silently discard a smaller initial packet,
// which would look like no QUIC at all.
const quicMinDatagram = 1200

// buildQUICProbe forges the long-header packet described above: a client
// Initial-shaped packet with a GREASE version, random-length-fixed
// connection IDs, padded to the minimum datagram size.
func buildQUICProbe() []byte {
	pkt := make([]byte, quicMinDatagram)
	// First byte: long header (0x80) + fixed bit (0x40). The low bits are
	// version-specific and irrelevant to a version-negotiation trigger.
	pkt[0] = 0xC3
	binary.BigEndian.PutUint32(pkt[1:5], quicGreaseVersion)
	// DCID: length then 8 bytes. The value only needs to be stable within
	// this one probe; the server echoes it in the Version Negotiation.
	pkt[5] = 8
	copy(pkt[6:14], []byte{0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef})
	// SCID: length then 8 bytes.
	pkt[14] = 8
	copy(pkt[15:23], []byte{0x74, 0x63, 0x70, 0x63, 0x61, 0x74, 0x71, 0x63}) // "tcpcatqc"
	// The remainder stays zero padding, taking the datagram to 1200 bytes.
	return pkt
}

// isQUICVersionNegotiation reports whether resp is a QUIC Version
// Negotiation packet: a long-header packet (high bit set) whose 32-bit
// version field is zero (RFC 9000 §17.2.1). That is the unambiguous marker
// of a QUIC server -- nothing else on UDP produces it.
func isQUICVersionNegotiation(resp []byte) bool {
	if len(resp) < 7 {
		return false
	}
	if resp[0]&0x80 == 0 { // not a long header
		return false
	}
	return binary.BigEndian.Uint32(resp[1:5]) == 0
}

// quicSupportedVersions extracts the list of versions a Version Negotiation
// packet advertises, for reporting. Layout after the version field:
// DCID-len, DCID, SCID-len, SCID, then a sequence of 4-byte versions.
func quicSupportedVersions(resp []byte) []uint32 {
	if !isQUICVersionNegotiation(resp) {
		return nil
	}
	i := 5
	if i >= len(resp) {
		return nil
	}
	dcidLen := int(resp[i])
	i += 1 + dcidLen
	if i >= len(resp) {
		return nil
	}
	scidLen := int(resp[i])
	i += 1 + scidLen

	var versions []uint32
	for i+4 <= len(resp) {
		versions = append(versions, binary.BigEndian.Uint32(resp[i:i+4]))
		i += 4
	}
	return versions
}

// quicProbe detects QUIC/HTTP/3 on UDP 443 via the version-negotiation
// trigger above.
var quicProbe = udpProbe{
	Name:    "quic",
	Payload: buildQUICProbe(),
	Match:   isQUICVersionNegotiation,
}
