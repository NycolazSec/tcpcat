package scan

import "github.com/NycolazSec/tcpcat/config"

// UseRawInsteadOfCopyModeXDP reports whether a scan that asked for --ebpf
// should run on the raw-socket engine because AF_XDP came up in copy mode.
//
// In copy mode the kernel still copies every frame, and a single thread owns
// the AF_XDP TX ring, so the engine was measured about 4x slower than the
// raw-socket engine (which sends from every core) on a full-range lab scan.
// --ebpf-copy keeps AF_XDP anyway; so does -f, since only the AF_XDP path
// fragments probes.
func UseRawInsteadOfCopyModeXDP(opts *config.Options, copyMode bool) bool {
	return copyMode && opts.UseXDP && !opts.EBPFCopy && !opts.Fragment
}

// FallBackToRawEngine turns an --ebpf scan into the raw-socket scan of the
// same kind: a UDP or ACK/Window/FIN/NULL/Xmas scan keeps its type, and the
// default, which --ebpf runs as a SYN scan, becomes -sS (without a scan type
// and without --ebpf, tcpcat would fall back to a connect scan).
func FallBackToRawEngine(opts *config.Options) {
	opts.UseXDP = false
	otherRaw := opts.AckScan || opts.WindowScan || opts.NullScan || opts.FinScan || opts.XmasScan
	if !opts.UdpScan && !otherRaw {
		opts.SynScan = true
	}
}
