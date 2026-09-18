package scan

import (
	"encoding/binary"
	"testing"
)

func TestSYNOptionsConstantsAgree(t *testing.T) {
	if len(synOptions) != synOptionsLen {
		t.Fatalf("len(synOptions) = %d, synOptionsLen = %d -- they must agree", len(synOptions), synOptionsLen)
	}
	// The TCP header length is measured in 32-bit words in the data-offset
	// field, so the option block has to be a whole number of words.
	if synTCPHeaderLen%4 != 0 {
		t.Errorf("synTCPHeaderLen = %d, want a multiple of 4", synTCPHeaderLen)
	}
	// Data offset is stored in the high nibble, in words.
	if got := byte(synDataOffset); got>>4 != synTCPHeaderLen/4 {
		t.Errorf("synDataOffset high nibble = %d words, want %d", got>>4, synTCPHeaderLen/4)
	}
}

func TestWriteSYNOptionsStampsTimestamp(t *testing.T) {
	buf := make([]byte, synOptionsLen)
	writeSYNOptions(buf)

	// The static option kinds must survive verbatim...
	for i, want := range synOptions {
		if i >= tsvalOffset && i < tsvalOffset+4 {
			continue // the TSval bytes are overwritten per call
		}
		if buf[i] != want {
			t.Errorf("byte %d = %#x, want %#x", i, buf[i], want)
		}
	}
	// ...while the TSval is a live, non-zero value rather than the zero
	// placeholder baked into synOptions.
	if tsval := binary.BigEndian.Uint32(buf[tsvalOffset : tsvalOffset+4]); tsval == 0 {
		t.Error("TSval = 0, want a per-probe timestamp")
	}
}

func TestWriteSYNOptionsAdvertisesNegotiatedOptions(t *testing.T) {
	buf := make([]byte, synOptionsLen)
	writeSYNOptions(buf)

	// A server can only echo SACK, timestamps or window scaling if the SYN
	// offered them first -- which is the whole point of sending options.
	want := map[byte]string{2: "MSS", 4: "SACK-permitted", 8: "Timestamps", 3: "Window scale"}
	seen := map[byte]bool{}
	for i := 0; i < len(buf); {
		kind := buf[i]
		if kind == 1 { // NOP
			i++
			continue
		}
		if kind == 0 || i+1 >= len(buf) {
			break
		}
		seen[kind] = true
		i += int(buf[i+1])
	}
	for kind, name := range want {
		if !seen[kind] {
			t.Errorf("SYN options do not advertise %s (kind %d)", name, kind)
		}
	}
}

func TestMPTCPOptionBlock(t *testing.T) {
	if synMPTCPOptionsLen != synOptionsLen+mpCapableLen {
		t.Fatalf("synMPTCPOptionsLen = %d, want synOptionsLen+mpCapableLen = %d", synMPTCPOptionsLen, synOptionsLen+mpCapableLen)
	}
	if synMPTCPOptionsLen != 32 {
		t.Fatalf("synMPTCPOptionsLen = %d, want 32 (20 base + 12 MP_CAPABLE)", synMPTCPOptionsLen)
	}
	if synMPTCPHeaderLen%4 != 0 {
		t.Errorf("synMPTCPHeaderLen = %d, want a multiple of 4", synMPTCPHeaderLen)
	}
	if got := byte(synMPTCPDataOffset); got>>4 != synMPTCPHeaderLen/4 {
		t.Errorf("synMPTCPDataOffset high nibble = %d words, want %d", got>>4, synMPTCPHeaderLen/4)
	}

	buf := make([]byte, synMPTCPOptionsLen)
	writeSYNOptionsMPTCP(buf)

	// The first 20 bytes are the standard block, TSval stamped.
	if binary.BigEndian.Uint32(buf[tsvalOffset:tsvalOffset+4]) == 0 {
		t.Error("TSval = 0, want a per-probe timestamp in the base block")
	}
	// The MP_CAPABLE option (kind 30) follows immediately.
	if buf[synOptionsLen] != mpCapableKind {
		t.Errorf("byte %d = %d, want MP_CAPABLE kind %d", synOptionsLen, buf[synOptionsLen], mpCapableKind)
	}
	if buf[synOptionsLen+1] != mpCapableLen {
		t.Errorf("MP_CAPABLE length = %d, want %d", buf[synOptionsLen+1], mpCapableLen)
	}
	// The 8-byte sender key must be stamped, not left zero.
	if binary.BigEndian.Uint64(buf[synOptionsLen+4:synMPTCPOptionsLen]) == 0 {
		t.Error("MP_CAPABLE sender key = 0, want a per-probe value")
	}
}
