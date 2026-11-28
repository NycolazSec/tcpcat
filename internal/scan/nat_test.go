package scan

import (
	"net"
	"testing"
)

func TestBehindNAT(t *testing.T) {
	for _, c := range []struct {
		local, target string
		want          bool
	}{
		{"192.168.1.20", "203.0.113.10", true}, // home box to the internet
		{"10.0.0.5", "198.51.100.7", true},
		{"100.72.1.9", "203.0.113.10", true},    // carrier-grade NAT
		{"192.168.1.20", "192.168.1.1", false},  // same network, no translation
		{"203.0.113.5", "198.51.100.7", false},  // public source: a server
		{"192.168.1.20", "127.0.0.1", false},    // loopback
		{"192.168.1.20", "100.64.0.1", false},   // carrier space is not the internet
		{"fd00::5", "2001:db8::1", true},        // IPv6 unique-local behind NPTv6
		{"2001:db8::5", "2001:db8:1::1", false}, // global IPv6, no translation
	} {
		if got := behindNAT(net.ParseIP(c.local), net.ParseIP(c.target)); got != c.want {
			t.Errorf("behindNAT(%s, %s) = %v, want %v", c.local, c.target, got, c.want)
		}
	}
}

func TestSourceBehindNATSkipsPrivateTargets(t *testing.T) {
	if _, ok := SourceBehindNAT([]string{"127.0.0.1", "192.168.1.1", "not-an-ip"}); ok {
		t.Error("no public target: there is no router to cross")
	}
}
