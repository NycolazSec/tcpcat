// internal/scan/udp.go
package scan

import (
	"fmt"
	"net"
	"strings"
	"time"

	"tcpcat/config"
)

// ScanUDPPort envoie une sonde UDP et analyse la réponse ou les erreurs ICMP.
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

	// Envoi d'un datagramme vide ou personnalisé
	payload := []byte{}
	if opts != nil && opts.DataString != "" {
		payload = []byte(opts.DataString)
	}
	_, _ = conn.Write(payload)

	// On place un délai strict pour l'attente de réponse
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)

	duration := time.Since(t0)
	latencyMs := float64(duration.Microseconds()) / 1000.0

	if err != nil {
		errStr := err.Error()

		// 1. Si l'OS remonte un refus, c'est qu'il a reçu un ICMP Port Unreachable
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

		// 2. Si le délai est dépassé, le port est muet (Open|Filtered)
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

		// Autre erreur inattendue
		return TargetResult{
			IP:        ip,
			Port:      port,
			State:     StateOpenFiltered,
			Latency:   duration,
			LatencyMs: latencyMs,
			Reason:    fmt.Sprintf("Error: %v", errStr),
		}
	}

	// 3. Si on reçoit des données directement en retour, le port est OUVERT
	return TargetResult{
		IP:        ip,
		Port:      port,
		State:     StateOpen,
		Latency:   duration,
		LatencyMs: latencyMs,
		Reason:    "UDP Response Received",
	}
}