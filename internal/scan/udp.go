// internal/scan/udp.go
package scan

import (
	"fmt"
	"net"
	"strings"
	"time"

	"tcpcat/config"
)

// ScanUDPPort sends a UDP probe and analyzes the response or ICMP errors.
func ScanUDPPort(ip string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	t0 := time.Now()
	targetAddr := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("udp", targetAddr, timeout)
	if err != nil {
		return TargetResult{
			IP:      ip,
			Port:    port,
			State:   StateClosed,
			Reason:  "Socket Error",
		}
	}
	defer conn.Close()

	// Send an empty or custom datagram
	payload := []byte{}
	if opts != nil && opts.DataString != "" {
		payload = []byte(opts.DataString)
	}
	_, _ = conn.Write(payload)

	// Set a strict deadline for waiting for a response
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)

	duration := time.Since(t0)
	latencyMs := float64(duration.Microseconds()) / 1000.0

	if err != nil {
		errStr := err.Error()

		// 1. If the OS reports a refusal, it means it received an ICMP Port Unreachable
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

		// 2. If the deadline is exceeded, the port is silent (Open|Filtered)
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

		// Other unexpected error
		return TargetResult{
			IP:        ip,
			Port:      port,
			State:     StateOpenFiltered,
			Latency:   duration,
			LatencyMs: latencyMs,
			Reason:    fmt.Sprintf("Error: %v", errStr),
		}
	}

	// 3. If we receive data directly in return, the port is OPEN
	return TargetResult{
		IP:        ip,
		Port:      port,
		State:     StateOpen,
		Latency:   duration,
		LatencyMs: latencyMs,
		Reason:    "UDP Response Received",
	}
}