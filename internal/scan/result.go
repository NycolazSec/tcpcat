// internal/scan/result.go
package scan

import "time"

const (
	StateOpen       = "OPEN"
	StateClosed     = "CLOSED"
	StateFiltered   = "FILTERED"
	StateUnfiltered = "UNFILTERED"
)

type TargetResult struct {
	Host      string        `json:"host"`
	IP        string        `json:"ip"`
	Port      int           `json:"port"`
	State     string        `json:"state"`
	Service   string        `json:"service,omitempty"`
	Banner    string        `json:"banner,omitempty"`
	Latency   time.Duration `json:"latency"`
	LatencyMs float64       `json:"latency_ms"`
	Reason    string        `json:"reason"`
}