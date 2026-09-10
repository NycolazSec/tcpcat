package osdetect

import "testing"

// buildSynAckFrame constructs a minimal Ethernet+IPv4+TCP frame with the
// given TTL/window/options so ParseTCPSignature/ClassifyOS can be exercised
// without needing a real capture.
func buildSynAckFrame(ttl uint8, window uint16, options []byte) []byte {
	const ipStart = 14
	const tcpStart = ipStart + 20

	optLen := len(options)
	for optLen%4 != 0 {
		options = append(options, 0) // pad to a 4-byte boundary like a real stack would
		optLen++
	}
	dataOffset := byte((20 + optLen) / 4)

	frame := make([]byte, tcpStart+20+optLen)
	frame[ipStart+8] = ttl
	frame[tcpStart+12] = dataOffset << 4
	frame[tcpStart+14] = byte(window >> 8)
	frame[tcpStart+15] = byte(window)
	copy(frame[tcpStart+20:], options)
	return frame
}

func TestParseTCPSignatureLinuxLike(t *testing.T) {
	// MSS(1460), SACK-perm, Timestamps, NOP, WScale(7) — mirrors the Linux
	// fingerprint entry's option order exactly.
	opts := []byte{
		2, 4, 0x05, 0xB4, // MSS kind=2 len=4 value=1460
		4, 2, // SACK-permitted kind=4 len=2
		8, 10, 0, 0, 0, 0, 0, 0, 0, 0, // Timestamps kind=8 len=10
		1,          // NOP
		3, 3, 0x07, // WScale kind=3 len=3 value=7
	}
	frame := buildSynAckFrame(64, 29200, opts)

	sig, ok := ParseTCPSignature(frame, 14, 34)
	if !ok {
		t.Fatal("expected ParseTCPSignature to succeed")
	}
	if sig.TTL != 64 {
		t.Errorf("TTL = %d, want 64", sig.TTL)
	}
	if sig.Window != 29200 {
		t.Errorf("Window = %d, want 29200", sig.Window)
	}
	if sig.MSS != 1460 {
		t.Errorf("MSS = %d, want 1460", sig.MSS)
	}
	if sig.WScale != 7 {
		t.Errorf("WScale = %d, want 7", sig.WScale)
	}
	if !sig.SACKPerm {
		t.Error("expected SACKPerm = true")
	}
	if !sig.TSPerm {
		t.Error("expected TSPerm = true")
	}
}

func TestParseTCPSignatureTooShort(t *testing.T) {
	frame := make([]byte, 30)
	if _, ok := ParseTCPSignature(frame, 14, 34); ok {
		t.Fatal("expected ok=false for a truncated frame")
	}
}

func TestMatchIdentifiesLinux(t *testing.T) {
	linux := KnownFingerprints[0]
	if linux.Name != "Linux 3.x-5.x" {
		t.Fatalf("test assumes KnownFingerprints[0] is Linux, got %s", linux.Name)
	}

	name, confidence := Match(linux.Sig)
	if name != "Linux 3.x-5.x" {
		t.Errorf("Match(exact Linux signature) = %q, want %q", name, linux.Name)
	}
	if confidence < 0.9 {
		t.Errorf("confidence for an exact match = %.2f, want >= 0.9", confidence)
	}
}

func TestMatchLowConfidenceReturnsEmpty(t *testing.T) {
	// SACKPerm=false + TSPerm=true matches none of the four DB entries'
	// combinations, and the WScale/MSS/option order below don't appear in
	// any of them either, so no fingerprint should clear the 0.4 threshold.
	noise := TCPSignature{
		TTL: 200, Window: 1, MSS: 9999, WScale: 50,
		SACKPerm: false, TSPerm: true,
		OptOrder: []byte{50, 51, 52},
	}
	name, confidence := Match(noise)
	if name != "" || confidence != 0 {
		t.Errorf("Match(noise) = (%q, %.2f), want (\"\", 0)", name, confidence)
	}
}

func TestClassifyOSEndToEnd(t *testing.T) {
	// Windows-like option order: MSS, NOP, WScale, NOP, NOP, SACK-perm.
	opts := []byte{
		2, 4, 0x05, 0xB4,
		1,
		3, 3, 0x08,
		1, 1,
		4, 2,
	}
	frame := buildSynAckFrame(128, 65535, opts)

	name, confidence := ClassifyOS(frame, 14, 34)
	if name != "Windows 10/11" {
		t.Errorf("ClassifyOS = %q (confidence %.2f), want Windows 10/11", name, confidence)
	}
}

func TestOptOrderSimilarity(t *testing.T) {
	cases := []struct {
		a, b []byte
		want float64
	}{
		{[]byte{2, 4, 8}, []byte{2, 4, 8}, 1.0},
		{[]byte{2, 4, 8}, []byte{}, 0.0},
		{[]byte{2, 4, 8}, []byte{8, 4, 2}, 1.0 / 3.0},
	}
	for _, c := range cases {
		got := optOrderSimilarity(c.a, c.b)
		if got != c.want {
			t.Errorf("optOrderSimilarity(%v, %v) = %.3f, want %.3f", c.a, c.b, got, c.want)
		}
	}
}
