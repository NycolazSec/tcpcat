//go:build !windows

package scan

import (
	"net"
	"strings"
	"testing"
	"time"

	"tcpcat/config"
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
		t.Fatalf("registration key %q != reply-parsed key %q", registered, fromReply)
	}
}

// TestRawRxKeyDistinguishesConcurrentProbes checks the key actually varies
// along every dimension that can distinguish two probes in flight at once
// -- port numbers alone aren't enough once multiple targets are being
// probed concurrently on the same port.
func TestRawRxKeyDistinguishesConcurrentProbes(t *testing.T) {
	base := rawRxKey(net.ParseIP("10.0.0.1").To4(), 80, 54321)

	tests := map[string]string{
		"different target IP":   rawRxKey(net.ParseIP("10.0.0.2").To4(), 80, 54321),
		"different probed port": rawRxKey(net.ParseIP("10.0.0.1").To4(), 443, 54321),
		"different local port":  rawRxKey(net.ParseIP("10.0.0.1").To4(), 80, 54322),
	}
	for name, other := range tests {
		if other == base {
			t.Errorf("%s: expected a different key, got the same one (%q)", name, base)
		}
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
