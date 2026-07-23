// internal/scan/connect.go
package scan

import (
	"fmt"
	"net"
	"strings"
	"time"

	"tcpcat/config"
	"tcpcat/internal/evasion"
)

// ScanConnectPort effectue un TCP Connect scan et injecte le payload si défini.
func ScanConnectPort(hostIP string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	res := TargetResult{
		Host:  hostIP,
		IP:    hostIP,
		Port:  port,
		State: StateFiltered,
	}

	targetAddr := fmt.Sprintf("%s:%d", hostIP, port)

	var conn net.Conn
	var err error
	t0 := time.Now()

	// Utilisation du dialer d'évasion si un port source ou TTL est configuré
	if opts != nil && (opts.SourcePort > 0 || opts.TTL > 0) {
		cfg, _ := evasion.NewConfig(opts.SourcePort, opts.TTL, opts.DataString, opts.DataHex, "")
		dialer := evasion.NewCustomDialer(cfg, timeout)
		conn, err = dialer.Dial("tcp", targetAddr)
	} else {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = dialer.Dial("tcp", targetAddr)
	}

	latency := time.Since(t0)
	res.Latency = latency
	res.LatencyMs = float64(latency.Microseconds()) / 1000.0

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			res.State = StateFiltered
			res.Reason = "Connection Timeout"
		} else if strings.Contains(err.Error(), "refused") {
			res.State = StateClosed
			res.Reason = "Connection Refused"
		} else {
			res.State = StateFiltered
			res.Reason = err.Error()
		}
		return res
	}

	defer conn.Close()

	// Envoi du payload dans la connexion TCP
	if opts != nil {
		payload, _ := evasion.PreparePayload(opts.DataString, opts.DataHex)
		if len(payload) > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(payload)
		}
	}

	res.State = StateOpen
	res.Reason = "SYN-ACK Received"
	return res
}