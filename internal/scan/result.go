package scan

import (
	"time"

	"tcpcat/internal/service"
	"tcpcat/internal/vuln"
)

const (
	StateOpen         = "OPEN"
	StateClosed       = "CLOSED"
	StateFiltered     = "FILTERED"
	StateUnfiltered   = "UNFILTERED"
	StateOpenFiltered = "OPEN|FILTERED"
)

type TargetResult struct {
	IP              string                  `json:"ip"`
	Port            int                     `json:"port"`
	State           string                  `json:"state"`
	Service         string                  `json:"service,omitempty"`
	Version         string                  `json:"version,omitempty"`
	Banner          string                  `json:"banner,omitempty"`
	OS              string                  `json:"os,omitempty"`
	TLS             *service.TLSInfo        `json:"tls,omitempty"`
	Latency         time.Duration           `json:"latency_ns"`
	LatencyMs       float64                 `json:"latency_ms"`
	Reason          string                  `json:"reason"`
	RiskSeverity    string                  `json:"risk_severity,omitempty"`
	Vulnerabilities []vuln.Vulnerability    `json:"vulnerabilities,omitempty"`
	Assessment      VulnerabilityAssessment `json:"vulnerability_assessment,omitempty"`
}

type VulnerabilityAssessment struct {
	Status     string    `json:"status,omitempty"`
	Source     string    `json:"source,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	AssessedAt time.Time `json:"assessed_at,omitempty"`
}
