package scan

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"tcpcat/config"
)

func ScanUDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, relayIP net.IP, rtt *RTTEstimator) TargetResult {
	targetAddr := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("udp", targetAddr, timeout)
	if err != nil {
		return TargetResult{
			IP:     ip,
			Port:   port,
			State:  StateClosed,
			Reason: "Socket Error",
		}
	}
	defer func() { _ = conn.Close() }()

	if relayIP != nil || spoofedSrcIP != nil {
		return TargetResult{
			IP:     ip,
			Port:   port,
			State:  StateFiltered,
			Reason: "UDP spoofing/relay requires raw socket support; userspace UDP connect cannot spoof source IP",
		}
	}

	payload := []byte{}
	if opts != nil && opts.DataString != "" {
		payload = []byte(opts.DataString)
	}

	attemptTimeout := probeTimeout(rtt, timeout)
	attempts := probeAttempts(opts)
	buf := make([]byte, 1024)

	var duration time.Duration
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		t0 := time.Now()
		_, _ = conn.Write(payload)

		_ = conn.SetReadDeadline(time.Now().Add(attemptTimeout))
		_, err = conn.Read(buf)
		duration = time.Since(t0)

		if err == nil {
			if rtt != nil {
				rtt.Sample(duration)
			}
			return TargetResult{
				IP:        ip,
				Port:      port,
				State:     StateOpen,
				Latency:   duration,
				LatencyMs: float64(duration.Microseconds()) / 1000.0,
				Reason:    "UDP Response Received",
			}
		}

		lastErr = err
		if strings.Contains(err.Error(), "connection refused") {
			// ICMP port-unreachable is authoritative; a retry can't
			// change a closed verdict, so don't burn the extra RTTs.
			break
		}
	}

	latencyMs := float64(duration.Microseconds()) / 1000.0
	errStr := lastErr.Error()

	if strings.Contains(errStr, "connection refused") {
		return TargetResult{
			IP:        ip,
			Port:      port,
			State:     StateClosed,
			Latency:   duration,
			LatencyMs: latencyMs,
			Reason:    "ICMP Port Unreachable",
		}
	}

	if netErr, ok := lastErr.(net.Error); ok && netErr.Timeout() {
		return TargetResult{
			IP:        ip,
			Port:      port,
			State:     StateOpenFiltered,
			Latency:   duration,
			LatencyMs: latencyMs,
			Reason:    "No Response (Timeout)",
		}
	}

	return TargetResult{
		IP:        ip,
		Port:      port,
		State:     StateOpenFiltered,
		Latency:   duration,
		LatencyMs: latencyMs,
		Reason:    fmt.Sprintf("Error: %v", errStr),
	}
}
