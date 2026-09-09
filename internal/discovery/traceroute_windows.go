//go:build windows

package discovery

import "time"

type HopResult struct {
	Hop       int           `json:"hop"`
	IP        string        `json:"ip"`
	Hostname  string        `json:"hostname"`
	Latency   time.Duration `json:"latency"`
	LatencyMs float64       `json:"latency_ms"`
	Reached   bool          `json:"reached"`
}

func RunTraceroute(targetIP string, port int, maxHops int, timeout time.Duration) []HopResult {
	return nil
}
