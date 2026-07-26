package scan

import (
	"fmt"
	"net"
	"strings"
	"time"

	"tcpcat/config"
)

func ScanUDPPort(ip string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	t0 := time.Now()
	targetAddr := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("udp", targetAddr, timeout)
	if err != nil {
		return TargetResult{
			IP:     ip,
			Port:   port,
			State:  StateClosed,
			Reason: "Socket Error",
		}
	}
	defer conn.Close()

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
