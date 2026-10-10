package scan

import (
	"time"

	"github.com/NycolazSec/tcpcat/internal/service"
	"github.com/NycolazSec/tcpcat/internal/vuln"
)

const (
	StateOpen         = "OPEN"
	StateClosed       = "CLOSED"
	StateFiltered     = "FILTERED"
	StateUnfiltered   = "UNFILTERED"
	StateOpenFiltered = "OPEN|FILTERED"
)

type TargetResult struct {
	IP              string                   `json:"ip"`
	Port            int                      `json:"port"`
	State           string                   `json:"state"`
	Service         string                   `json:"service,omitempty"`
	Version         string                   `json:"version,omitempty"`
	Banner          string                   `json:"banner,omitempty"`
	OS              string                   `json:"os,omitempty"`
	OSConfidence    float64                  `json:"os_confidence,omitempty"`
	MPTCP           bool                     `json:"mptcp,omitempty"`
	TLS             *service.TLSInfo         `json:"tls,omitempty"`
	JARM            *service.JARMInfo        `json:"jarm,omitempty"`
	HTTPPosture     *service.HTTPPostureInfo `json:"http_posture,omitempty"`
	SSHPosture      *service.SSHPostureInfo  `json:"ssh_posture,omitempty"`
	Findings        []string                 `json:"findings,omitempty"`
	Latency         time.Duration            `json:"latency_ns"`
	LatencyMs       float64                  `json:"latency_ms"`
	Reason          string                   `json:"reason"`
	RiskSeverity    string                   `json:"risk_severity,omitempty"`
	Vulnerabilities []vuln.Vulnerability     `json:"vulnerabilities,omitempty"`
	Assessment      VulnerabilityAssessment  `json:"vulnerability_assessment,omitempty"`
	DualStack       *DualStackInfo           `json:"dual_stack,omitempty"`
}

// DualStackInfo marks an IPv6 result whose port is open on IPv6 but not on
// the IPv4 address published for the same name (see internal/dualstack).
type DualStackInfo struct {
	Gap         string `json:"gap"`
	Name        string `json:"name"`
	Counterpart string `json:"ipv4_counterpart"`
	Sensitive   bool   `json:"sensitive_port"`
}

type VulnerabilityAssessment struct {
	Status     string    `json:"status,omitempty"`
	Source     string    `json:"source,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	AssessedAt time.Time `json:"assessed_at,omitempty"`
}
