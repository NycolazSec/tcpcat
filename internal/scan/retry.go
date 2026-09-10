package scan

import (
	"time"

	"tcpcat/config"
)

// probeAttempts returns how many times a stateless probe (SYN/ACK/Window/
// FIN/NULL/Xmas/UDP, over either the raw-socket or AF_XDP path) should be
// sent before the target is reported filtered. A single dropped packet at
// scan rate is common on lossy paths or under load, and previously
// misclassified an open port as filtered on the first missed reply; this
// mirrors nmap/zmap/masscan, which all retransmit by default.
func probeAttempts(opts *config.Options) int {
	retries := 2
	if opts != nil && opts.MaxRetries >= 0 {
		retries = opts.MaxRetries
	}
	return retries + 1
}

// probeTimeout returns how long a single attempt should wait for a reply.
// Once the shared RTT estimator has enough samples, it uses an RFC
// 6298-style RTO (SRTT + 4*RTTVAR) floored at a quarter of the timing
// template's timeout, so a fast/healthy target gets its retries resolved
// well inside the old fixed wait instead of always paying for it in full.
// Before the estimator has samples (or when rtt is nil), it falls back to
// the caller's configured timeout unchanged.
func probeTimeout(rtt *RTTEstimator, fallback time.Duration) time.Duration {
	if rtt == nil || !rtt.HasSamples() {
		return fallback
	}
	return rtt.RTO(fallback / 4)
}
