package scan

import (
	"encoding/binary"
	"time"
)

// The TCP option block advertised on every SYN probe: MSS, SACK-permitted,
// Timestamps, NOP, Window scale -- the same set and order a modern Linux
// client sends.
//
// This is not cosmetic, and it is why both send paths share it. SACK,
// timestamps and window scaling are *negotiated*: a server may only use
// them in its SYN/ACK if the client offered them first. A SYN carrying no
// options at all therefore guarantees an option-less SYN/ACK from every
// target, whatever it runs -- which is precisely the signature of a
// minimal network-gear stack, so OS fingerprinting matched healthy Linux
// hosts (scanme.nmap.org among them) against the Cisco IOS entry.
// Advertising a realistic set lets the reply reflect the target's own
// stack, which is what osdetect scores.
//
// Only a SYN carries these. A bare ACK, NULL, FIN or Xmas probe is
// deliberately minimal -- options there would be both pointless (nothing
// is being negotiated) and a fingerprint of the scanner itself.
var synOptions = []byte{
	2, 4, 0x05, 0xB4, // MSS = 1460
	4, 2, // SACK permitted
	8, 10, 0, 0, 0, 0, 0, 0, 0, 0, // Timestamps (TSval stamped per probe)
	1,       // NOP, aligning the next option to a word boundary
	3, 3, 7, // Window scale, shift 7
}

const (
	synOptionsLen   = 20                 // len(synOptions), asserted by a test
	synTCPHeaderLen = 20 + synOptionsLen // 40 bytes: 10 32-bit words
	synDataOffset   = (synTCPHeaderLen / 4) << 4
	tsvalOffset     = 8 // TSval's position within synOptions
)

// writeSYNOptions copies the option block into dst (which must be at least
// synOptionsLen long) and stamps a fresh timestamp value. A constant TSval
// looks synthetic and invites middleboxes to strip the option, taking the
// negotiation -- and the fingerprint -- with it.
func writeSYNOptions(dst []byte) {
	copy(dst[:synOptionsLen], synOptions)
	binary.BigEndian.PutUint32(dst[tsvalOffset:tsvalOffset+4], uint32(time.Now().UnixMilli()))
}

// mpCapableOption is a Multipath TCP MP_CAPABLE option (kind 30, RFC 8684)
// for a SYN: subtype 0, version 1, carrying an 8-byte sender key. It is
// appended to the SYN option block only under --mptcp.
//
// A target that also speaks MPTCP answers with its own MP_CAPABLE in the
// SYN/ACK, so the mere presence of option 30 in the reply identifies a
// multipath-capable stack -- an OS-default on recent Apple/Android devices
// and on operator and CDN front ends (Cloudflare). It costs no extra
// bandwidth: the option rides in the SYN the scan already sends, and the
// handshake is never completed (the key's value is irrelevant, only the
// option's presence in the reply matters).
var mpCapableOption = []byte{
	30,                     // kind: MPTCP
	12,                     // length
	0x01,                   // subtype 0 (MP_CAPABLE, high nibble) | version 1 (low nibble)
	0x01,                   // flags: H = HMAC-SHA256, the RFC 8684 v1 baseline
	0, 0, 0, 0, 0, 0, 0, 0, // sender key, stamped per probe
}

const (
	mpCapableLen       = 12
	mpCapableKind      = 30
	synMPTCPOptionsLen = synOptionsLen + mpCapableLen // 32 bytes, 4-byte aligned
	synMPTCPHeaderLen  = 20 + synMPTCPOptionsLen      // 52 bytes = 13 words
	synMPTCPDataOffset = (synMPTCPHeaderLen / 4) << 4 // data-offset nibble
)

// writeSYNOptionsMPTCP writes the standard SYN options followed by an
// MP_CAPABLE option, stamping the per-probe TSval and a fresh MP_CAPABLE
// sender key. dst must be at least synMPTCPOptionsLen bytes. Both blocks
// are 4-byte aligned, so the combined header needs no padding.
func writeSYNOptionsMPTCP(dst []byte) {
	writeSYNOptions(dst[:synOptionsLen])
	copy(dst[synOptionsLen:synMPTCPOptionsLen], mpCapableOption)
	binary.BigEndian.PutUint64(dst[synOptionsLen+4:synMPTCPOptionsLen], uint64(time.Now().UnixNano()))
}
