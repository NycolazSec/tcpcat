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

	// Pick the probe(s) to send. An explicit --data-string overrides the
	// built-in protocol payloads (the operator is steering the scan by
	// hand); otherwise use the curated per-port probe, falling back to a
	// single empty datagram for a port with no known probe -- an empty
	// send is worthless for most UDP services but harmless, and a few
	// (some game and monitoring servers) do answer it.
	var probes []udpProbe
	if opts != nil && opts.DataString != "" {
		probes = []udpProbe{{Name: "", Payload: []byte(opts.DataString)}}
	} else if known := probesForPort(port); len(known) > 0 {
		probes = known
	} else {
		probes = []udpProbe{{Name: "", Payload: nil}}
	}

	attemptTimeout := probeTimeout(rtt, timeout)
	attempts := probeAttempts(opts)
	buf := make([]byte, 2048)

	var duration time.Duration
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		for _, probe := range probes {
			t0 := time.Now()
			_, _ = conn.Write(probe.Payload)

			_ = conn.SetReadDeadline(time.Now().Add(attemptTimeout))
			n, readErr := conn.Read(buf)
			duration = time.Since(t0)

			if readErr != nil {
				lastErr = readErr
				// ICMP port-unreachable is authoritative for the whole
				// port, not just this probe -- stop trying other probes.
				if strings.Contains(readErr.Error(), "connection refused") {
					break
				}
				continue
			}

			// A reply arrived. If this probe knows how to recognise its
			// own protocol, a matching reply is a positive service ID; a
			// non-matching one still proves the port is open (something is
			// listening and chose to answer) but isn't attributed.
			resp := buf[:n]
			reason := "UDP Response Received"
			if probe.Name != "" {
				if probe.Match == nil || probe.Match(resp) {
					reason = "UDP Response Received (" + probe.Name + ")"
				}
			}
			if rtt != nil {
				rtt.Sample(duration)
			}
			result := TargetResult{
				IP:        ip,
				Port:      port,
				State:     StateOpen,
				Latency:   duration,
				LatencyMs: float64(duration.Microseconds()) / 1000.0,
				Reason:    reason,
			}
			if probe.Name != "" && (probe.Match == nil || probe.Match(resp)) {
				result.Service = probe.Name
			}
			return result
		}

		// Every probe this attempt failed. ICMP port-unreachable is
		// authoritative -- a closed verdict won't change on retry, so stop
		// burning RTTs on it.
		if lastErr != nil && strings.Contains(lastErr.Error(), "connection refused") {
			break
		}
	}

	if lastErr == nil {
		// Should not happen (a nil-error read returns inside the loop), but
		// guard rather than nil-deref if the loop ever exits some other way.
		return TargetResult{IP: ip, Port: port, State: StateOpenFiltered, Reason: "No Response"}
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
