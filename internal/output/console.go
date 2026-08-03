// internal/output/console.go
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"tcpcat/internal/scan"
)

type JSONReport struct {
	Target   string              `json:"target"`
	Duration string              `json:"duration"`
	Results  []scan.TargetResult `json:"results"`
}

func ExportJSON(filePath string, target string, results []scan.TargetResult, duration time.Duration) error {
	report := JSONReport{
		Target:   target,
		Duration: duration.Round(time.Millisecond).String(),
		Results:  results,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("json serialization error: %w", err)
	}

	return os.WriteFile(filePath, data, 0644)
}
