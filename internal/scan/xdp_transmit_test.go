//go:build linux

package scan

import (
	"testing"
	"time"
)

// The xdp library panics on an unexpected sendto error; xdpTransmit must turn
// any panic into an error and stop further sends, not crash the scan.
func TestXDPTransmitRecoversAndStopsSending(t *testing.T) {
	t.Cleanup(func() { xdpTxBroken.Store(false) })

	// A nil socket makes Transmit panic, standing in for the library's
	// panic on ENETDOWN.
	n, err := xdpTransmit(nil, nil)
	if err == nil || n != 0 {
		t.Fatalf("xdpTransmit on a failing socket = (%d, %v), want (0, an error)", n, err)
	}
	if !xdpTxBroken.Load() {
		t.Fatal("a failed transmit must mark the TX path broken")
	}

	withTxQueue(t, 1, time.Second)
	start := time.Now()
	if transmitXDPFrames(nil, [][]byte{[]byte("probe")}) {
		t.Fatal("transmitXDPFrames queued a frame after the TX path broke")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Error("transmitXDPFrames waited instead of failing at once on a broken TX path")
	}
	if got := xdpNotProbed(); got != "Not probed: AF_XDP transmit failed" {
		t.Errorf("reason = %q", got)
	}
}
