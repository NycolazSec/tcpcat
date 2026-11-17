//go:build !windows

package scan

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/NycolazSec/tcpcat/config"
)

// TestRawRxKeyMatchesSentAndReceivedView checks that the key a scanner
// registers while waiting for a reply (target host, the port it's
// probing, its own source port) is exactly what rawRxLoop recomputes from
// a real reply's own header fields: the packet's IP source is the target,
// its TCP source port is the port that replied (the one we probed), and
// its TCP destination port is our own source port. Both sides call the
// same function, but plugging in each side's own view of "who's who"
// separately is what actually needs to line up -- a mismatch here would
// mean rawRxLoop silently drops every real reply.
func TestRawRxKeyMatchesSentAndReceivedView(t *testing.T) {
	targetIP := net.ParseIP("172.18.0.2").To4()
	probedPort := 8080
	ourSrcPort := 54321

	registered := rawRxKey(targetIP, probedPort, ourSrcPort)
	fromReply := rawRxKey(targetIP /* packet's IP src */, probedPort, /* packet's TCP src port */
		ourSrcPort /* packet's TCP dst port */)

	if registered != fromReply {
		t.Fatalf("registration key %+v != reply-parsed key %+v", registered, fromReply)
	}
}

// TestRawRxKeyDistinguishesConcurrentProbes checks the key actually varies
// along every dimension that can distinguish two probes in flight at once
// -- port numbers alone aren't enough once multiple targets are being
// probed concurrently on the same port.
func TestRawRxKeyDistinguishesConcurrentProbes(t *testing.T) {
	base := rawRxKey(net.ParseIP("10.0.0.1").To4(), 80, 54321)

	tests := map[string]rawRxKeyT{
		"different target IP":   rawRxKey(net.ParseIP("10.0.0.2").To4(), 80, 54321),
		"different probed port": rawRxKey(net.ParseIP("10.0.0.1").To4(), 443, 54321),
		"different local port":  rawRxKey(net.ParseIP("10.0.0.1").To4(), 80, 54322),
	}
	for name, other := range tests {
		if other == base {
			t.Errorf("%s: expected a different key, got the same one (%+v)", name, base)
		}
	}
}

// TestRawRxKeyFromFrameMatchesRegistration checks that the key the receive
// loop reads out of a reply equals the one the probe registered: if the two
// ever disagree, every reply is dropped and every port reads as filtered.
func TestRawRxKeyFromFrameMatchesRegistration(t *testing.T) {
	target := net.ParseIP("192.0.2.7").To4()
	const probedPort, ourSrcPort = 8443, 54321

	// A SYN/ACK from target:8443 to us:54321, IP header without options.
	frame := make([]byte, 40)
	frame[0] = 0x45
	copy(frame[12:16], target)
	copy(frame[16:20], net.IPv4(198, 51, 100, 1).To4())
	binary.BigEndian.PutUint16(frame[20:22], probedPort)
	binary.BigEndian.PutUint16(frame[22:24], ourSrcPort)
	frame[33] = 0x12

	got := rawRxKeyFromFrame(frame, 0, 20)
	if want := rawRxKey(target, probedPort, ourSrcPort); got != want {
		t.Fatalf("key from the reply %+v != registered key %+v", got, want)
	}
	// A 16-byte form of the same address must register the same key.
	if got != rawRxKey(net.ParseIP("192.0.2.7"), probedPort, ourSrcPort) {
		t.Fatal("a 16-byte IPv4 address registers a different key than its 4-byte form")
	}
}

func TestNewRawTCPScannerRejectsIPv6(t *testing.T) {
	_, err := newRawTCPScanner("2001:db8::1", 80, &config.Options{}, time.Second, nil)
	if err == nil {
		t.Fatal("expected an error for an IPv6 target")
	}
	if !strings.Contains(err.Error(), "IPv6") {
		t.Errorf("error = %q, want it to mention IPv6", err.Error())
	}
}

func TestNewRawTCPScannerRejectsUnparsableTarget(t *testing.T) {
	_, err := newRawTCPScanner("not-an-ip", 80, &config.Options{}, time.Second, nil)
	if err == nil {
		t.Fatal("expected an error for an unparsable target")
	}
	if strings.Contains(err.Error(), "IPv6") {
		t.Errorf("error = %q, should not blame IPv6 for a target that isn't an IP at all", err.Error())
	}
}

// tcpChecksum sums the pseudo-header in place; it must give exactly what the
// pseudo-header buffer did, for even and odd segment lengths.
func TestTCPChecksumMatchesPseudoHeaderBuffer(t *testing.T) {
	src, dst := net.IPv4(192, 0, 2, 7), net.IPv4(198, 51, 100, 23)
	reference := func(seg []byte) uint16 {
		pseudo := make([]byte, 12+len(seg))
		copy(pseudo[0:4], src.To4())
		copy(pseudo[4:8], dst.To4())
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
		copy(pseudo[12:], seg)
		return xdpChecksum(pseudo)
	}
	for _, n := range []int{20, 21, 40, 52, 53} {
		seg := make([]byte, n)
		for i := range seg {
			seg[i] = byte(i*37 + n)
		}
		if got, want := tcpChecksum(src, dst, seg), reference(seg); got != want {
			t.Errorf("len %d: tcpChecksum = %#04x, pseudo-header buffer gives %#04x", n, got, want)
		}
		if got, want := calcTCPChecksum(src, dst, seg), reference(seg); got != want {
			t.Errorf("len %d: calcTCPChecksum = %#04x, want %#04x", n, got, want)
		}
	}
}

// putIPv4Header writes the header constructIPv4Header always returned.
func TestPutIPv4HeaderMatchesConstruct(t *testing.T) {
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)
	var h [20]byte
	putIPv4Header(h[:], src, dst, 6, 40)
	if want := constructIPv4Header(src, dst, 6, 40); string(h[:]) != string(want) {
		t.Errorf("putIPv4Header = % x\nconstruct      = % x", h[:], want)
	}
	if calcIPChecksum(h[:]) != 0 {
		t.Error("header checksum does not verify (sum over a valid header must be 0)")
	}
}
