package output

import (
	"fmt"
	"os"
	"time"

	"tcpcat/internal/scan"
)

func ExportNormal(filePath string, target string, results []scan.TargetResult, duration time.Duration) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("impossible de créer le fichier %s: %w", filePath, err)
	}
	defer file.Close()

	fmt.Fprintf(file, "# tcpcat 5.0 scan report for %s\n", target)
	fmt.Fprintf(file, "# Scan completed in %v\n\n", duration.Round(time.Millisecond))
	fmt.Fprintf(file, "%-10s %-10s %-15s %s\n", "PORT", "STATE", "SERVICE", "BANNER")
	fmt.Fprintf(file, "---------------------------------------------------\n")

	for _, r := range results {
		portStr := fmt.Sprintf("%d/tcp", r.Port)
		svc := r.Service
		if svc == "" {
			svc = "unknown"
		}
		fmt.Fprintf(file, "%-10s %-10s %-15s %s\n", portStr, r.State, svc, r.Banner)
	}

	return nil
}
