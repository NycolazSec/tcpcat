//go:build !windows

package scan

import (
	"strings"
	"testing"
	"time"

	"tcpcat/config"
)

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
