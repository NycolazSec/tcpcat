package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"tcpcat/internal/scan"
	"tcpcat/internal/service"
)

type JSONReport struct {
	Target   string              `json:"target"`
	Duration string              `json:"duration"`
	Results  []scan.TargetResult `json:"results"`
	// CertificateReuse lists every TLS certificate fingerprint observed on
	// more than one distinct host during this scan (see
	// service.FindReusedCertificates) -- ordinarily a shared load
	// balancer/CDN certificate, but also how an unintended shared private
	// key across otherwise-unrelated hosts would show up.
	CertificateReuse []service.CertReuseGroup `json:"certificate_reuse,omitempty"`
	// Summary aggregates every vulnerability across Results by severity
	// tier (critical first), each with the hosts it was found on -- see
	// scan.SummarizeSeverity.
	Summary []scan.SeveritySummaryEntry `json:"summary,omitempty"`
}

func ExportJSON(filePath string, target string, results []scan.TargetResult, duration time.Duration, certReuse []service.CertReuseGroup, summary []scan.SeveritySummaryEntry) error {
	report := JSONReport{
		Target:           target,
		Duration:         duration.Round(time.Millisecond).String(),
		Results:          results,
		CertificateReuse: certReuse,
		Summary:          summary,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("json serialization error: %w", err)
	}

	return os.WriteFile(filePath, data, 0600)
}
