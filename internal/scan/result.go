package scan

import "time"

const (
	StateOpen         = "OPEN"
	StateClosed       = "CLOSED"
	StateFiltered     = "FILTERED"
	StateUnfiltered   = "UNFILTERED"
	StateOpenFiltered = "OPEN|FILTERED"
)

type TargetResult struct {
	IP        string        `json:"ip"`
	Port      int           `json:"port"`
	State     string        `json:"state"`
	Service   string        `json:"service,omitempty"`
	Version   string        `json:"version,omitempty"`
	Banner    string        `json:"banner,omitempty"`
	OS        string        `json:"os,omitempty"`
	Latency   time.Duration `json:"latency_ns"`
	LatencyMs float64       `json:"latency_ms"`
	Reason    string        `json:"reason"`
}
