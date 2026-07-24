// internal/scan/result.go
package scan

import "time"

const (
	StateOpen         = "OPEN"
	StateClosed       = "CLOSED"
	StateFiltered     = "FILTERED"
	StateUnfiltered   = "UNFILTERED"
	StateOpenFiltered = "OPEN|FILTERED"
)

// TargetResult stocke l'état d'un port pour une adresse IP donnée.
type TargetResult struct {
	IP        string        `json:"ip"`
	Port      int           `json:"port"`
	State     string        `json:"state"`
	Service   string        `json:"service,omitempty"`
	Banner    string        `json:"banner,omitempty"`
	Latency   time.Duration `json:"latency_ns"`
	LatencyMs float64       `json:"latency_ms"`
	Reason    string        `json:"reason"`
}