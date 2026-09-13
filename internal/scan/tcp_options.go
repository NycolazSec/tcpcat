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
