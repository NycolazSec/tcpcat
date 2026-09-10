package output

import (
	"fmt"
	"os"
	"time"

	"tcpcat/internal/scan"
)

func ExportNormal(filePath string, target string, results []scan.TargetResult, duration time.Duration) error {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()

	if _, err := fmt.Fprintf(file, "# tcpcat 5.0 scan report for %s\n", target); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if _, err := fmt.Fprintf(file, "# Scan completed in %v\n\n", duration.Round(time.Millisecond)); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if _, err := fmt.Fprintf(file, "%-10s %-10s %-15s %s\n", "PORT", "STATE", "SERVICE", "BANNER"); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if _, err := fmt.Fprintf(file, "---------------------------------------------------\n"); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	for _, r := range results {
		portStr := fmt.Sprintf("%d/tcp", r.Port)
		svc := r.Service
		if svc == "" {
			svc = "unknown"
		}
		if _, err := fmt.Fprintf(file, "%-10s %-10s %-15s %s\n", portStr, r.State, svc, r.Banner); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}

	return nil
}
