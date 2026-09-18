package scan

import (
	"encoding/binary"
	"testing"
)

func TestBuildQUICProbe(t *testing.T) {
	pkt := buildQUICProbe()

	if len(pkt) != quicMinDatagram {
		t.Fatalf("probe length = %d, want %d (min QUIC initial datagram)", len(pkt), quicMinDatagram)
	}
	if pkt[0]&0x80 == 0 {
		t.Error("first byte high bit clear; want a long-header packet")
	}
	if v := binary.BigEndian.Uint32(pkt[1:5]); v != quicGreaseVersion {
		t.Errorf("version = %#x, want the GREASE version %#x that forces a Version Negotiation reply", v, quicGreaseVersion)
	}
	if pkt[5] != 8 {
		t.Errorf("DCID length = %d, want 8", pkt[5])
	}
}

func TestIsQUICVersionNegotiation(t *testing.T) {
	// A real Version Negotiation: long header + version field == 0.
	vn := []byte{0x80, 0, 0, 0, 0, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00}
	if !isQUICVersionNegotiation(vn) {
		t.Error("valid Version Negotiation not recognised")
	}

	// A long-header packet with a real (non-zero) version is NOT a VN.
	notVN := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0, 0, 0}
	if isQUICVersionNegotiation(notVN) {
		t.Error("a non-zero version must not be treated as Version Negotiation")
	}

	// A short-header (or plain UDP) response is not QUIC VN.
	shortHdr := []byte{0x40, 1, 2, 3, 4, 5, 6, 7}
	if isQUICVersionNegotiation(shortHdr) {
		t.Error("short-header/plain response wrongly treated as VN")
	}

	if isQUICVersionNegotiation([]byte{0x80, 0, 0}) {
		t.Error("a too-short response must not be treated as VN")
	}
}

func TestQUICSupportedVersions(t *testing.T) {
	// VN: long header, version 0, DCID len 0, SCID len 0, then two versions.
	vn := []byte{0x80, 0, 0, 0, 0,
		0x00,                   // DCID len
		0x00,                   // SCID len
		0x00, 0x00, 0x00, 0x01, // QUIC v1
		0x6b, 0x33, 0x43, 0xcf, // a draft/other version
	}
	versions := quicSupportedVersions(vn)
	if len(versions) != 2 || versions[0] != 0x00000001 || versions[1] != 0x6b3343cf {
		t.Errorf("versions = %#x, want [0x1 0x6b3343cf]", versions)
	}

	// Not a VN → no versions.
	if quicSupportedVersions([]byte{0xC0, 0, 0, 0, 1}) != nil {
		t.Error("non-VN packet should yield no versions")
	}
}
