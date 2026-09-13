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
