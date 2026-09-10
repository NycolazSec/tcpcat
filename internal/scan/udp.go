package scan

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"tcpcat/config"
)

func ScanUDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, relayIP net.IP) TargetResult {
	t0 := time.Now()
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
	_, _ = conn.Write(payload)

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)

	duration := time.Since(t0)
	latencyMs := float64(duration.Microseconds()) / 1000.0

	if err != nil {
		errStr := err.Error()

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

		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
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

	return TargetResult{
		IP:        ip,
		Port:      port,
		State:     StateOpen,
		Latency:   duration,
		LatencyMs: latencyMs,
		Reason:    "UDP Response Received",
	}
}
