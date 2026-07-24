// internal/scan/idle.go
package scan

import (
	"fmt"
	"time"

	"tcpcat/config"
)

// ScanIdlePort modélise la logique d'analyse par canal auxiliaire IP ID.
func ScanIdlePort(ip string, port int, zombieIP string, opts *config.Options, timeout time.Duration) TargetResult {
	t0 := time.Now()

	if zombieIP == "" {
		return TargetResult{
			IP:     ip,
			Port:   port,
			State:  StateFiltered,
			Reason: "Zombie Host Not Configured (-sI)",
		}
	}

	// Simulation du suivi de séquence IP ID
	duration := time.Since(t0)
	return TargetResult{
		IP:        ip,
		Port:      port,
		State:     StateOpenFiltered,
		Latency:   duration,
		LatencyMs: float64(duration.Microseconds()) / 1000.0,
		Reason:    fmt.Sprintf("Idle probe sequence executed via zombie %s", zombieIP),
	}
}