package scan

import (
	"testing"

	"github.com/NycolazSec/tcpcat/config"
)

func TestUseRawInsteadOfCopyModeXDP(t *testing.T) {
	cases := []struct {
		name     string
		opts     config.Options
		copyMode bool
		want     bool
	}{
		{"zero-copy keeps AF_XDP", config.Options{UseXDP: true}, false, false},
		{"copy mode falls back", config.Options{UseXDP: true}, true, true},
		{"--ebpf-copy keeps AF_XDP", config.Options{UseXDP: true, EBPFCopy: true}, true, false},
		{"-f needs the AF_XDP path", config.Options{UseXDP: true, Fragment: true}, true, false},
		{"no --ebpf, nothing to do", config.Options{}, true, false},
	}
	for _, c := range cases {
		if got := UseRawInsteadOfCopyModeXDP(&c.opts, c.copyMode); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFallBackToRawEngineKeepsTheScanType(t *testing.T) {
	plain := config.Options{UseXDP: true}
	FallBackToRawEngine(&plain)
	if plain.UseXDP || !plain.SynScan {
		t.Errorf("plain --ebpf scan: UseXDP=%v SynScan=%v, want a raw SYN scan", plain.UseXDP, plain.SynScan)
	}
	udp := config.Options{UseXDP: true, UdpScan: true}
	FallBackToRawEngine(&udp)
	if udp.UseXDP || udp.SynScan || !udp.UdpScan {
		t.Errorf("--ebpf -sU: UseXDP=%v SynScan=%v UdpScan=%v, want a raw UDP scan", udp.UseXDP, udp.SynScan, udp.UdpScan)
	}
	ack := config.Options{UseXDP: true, AckScan: true}
	FallBackToRawEngine(&ack)
	if ack.SynScan || !ack.AckScan {
		t.Errorf("--ebpf -sA: SynScan=%v AckScan=%v, want the ACK scan kept", ack.SynScan, ack.AckScan)
	}
}
