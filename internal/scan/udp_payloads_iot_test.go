package scan

import "testing"

func TestIoTProbesRegistered(t *testing.T) {
	cases := map[int]string{
		623:  "ipmi",
		5683: "coap",
	}
	for port, name := range cases {
		probes := probesForPort(port)
		if len(probes) == 0 {
			t.Errorf("port %d has no probe registered", port)
			continue
		}
		if probes[0].Name != name {
			t.Errorf("port %d probe = %q, want %q", port, probes[0].Name, name)
		}
	}
}

func TestCoapMatch(t *testing.T) {
	// A valid CoAP reply: ver=1 (0x60 = ver1,type ACK), code 2.05 (0x45),
	// echoing message ID 0x1337.
	valid := []byte{0x60, 0x45, 0x13, 0x37, 0xff, 'd', 'a', 't', 'a'}
	if !coapProbe.Match(valid) {
		t.Errorf("valid CoAP reply not matched")
	}
	// Wrong version bits.
	if coapProbe.Match([]byte{0x00, 0x45, 0x13, 0x37}) {
		t.Errorf("non-CoAP byte matched")
	}
	// Wrong message ID.
	if coapProbe.Match([]byte{0x60, 0x45, 0x00, 0x00}) {
		t.Errorf("mismatched message ID matched")
	}
	if coapProbe.Match([]byte{0x60}) {
		t.Errorf("too-short reply matched")
	}
}

func TestCoapPayloadStructure(t *testing.T) {
	p := coapProbe.Payload
	want := []byte{0x40, 0x01, 0x13, 0x37, 0xbb}
	for i, b := range want {
		if p[i] != b {
			t.Fatalf("coap payload[%d] = %#x, want %#x", i, p[i], b)
		}
	}
	if string(p[5:16]) != ".well-known" {
		t.Errorf("coap Uri-Path 1 = %q, want .well-known", string(p[5:16]))
	}
	if p[16] != 0x04 || string(p[17:21]) != "core" {
		t.Errorf("coap Uri-Path 2 not 'core': %v", p[16:])
	}
}

func TestIpmiMatch(t *testing.T) {
	valid := []byte{0x06, 0x00, 0xff, 0x07, 0x00, 0x00}
	if !ipmiProbe.Match(valid) {
		t.Errorf("valid IPMI RMCP reply not matched")
	}
	if ipmiProbe.Match([]byte{0x06, 0x00, 0xff, 0x06}) {
		t.Errorf("non-IPMI RMCP class matched")
	}
	if ipmiProbe.Match([]byte{0x06, 0x00}) {
		t.Errorf("too-short reply matched")
	}
}

func TestIpmiPayloadChecksums(t *testing.T) {
	// Verify the two IPMI message checksums are correct two's-complements,
	// so a real BMC accepts the request rather than dropping it.
	p := ipmiProbe.Payload
	// checksum1 covers rsAddr(idx 14) + netFn(idx 15); csum at idx 16.
	if byte(-(p[14] + p[15])) != p[16] {
		t.Errorf("IPMI checksum1 = %#x, want %#x", p[16], byte(-(p[14] + p[15])))
	}
	// checksum2 covers rqAddr..priv (idx 17..21); csum at idx 22.
	var sum byte
	for _, b := range p[17:22] {
		sum += b
	}
	if byte(-sum) != p[22] {
		t.Errorf("IPMI checksum2 = %#x, want %#x", p[22], byte(-sum))
	}
}
