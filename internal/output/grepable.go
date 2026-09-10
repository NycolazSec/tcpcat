package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	"tcpcat/internal/scan"
)

func ExportGrepable(filePath string, target string, results []scan.TargetResult, duration time.Duration) error {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()

	if _, err := fmt.Fprintf(file, "# tcpcat 5.0 scan report for %s\n", target); err != nil {
		return fmt.Errorf("write grepable report: %w", err)
	}

	var portEntries []string
	for _, r := range results {
		svc := r.Service
		if svc == "" {
			svc = "unknown"
		}
		portEntries = append(portEntries, fmt.Sprintf("%d/%s/%s//%s///", r.Port, strings.ToLower(r.State), "tcp", svc))
	}

	portsStr := strings.Join(portEntries, ", ")
	if _, err := fmt.Fprintf(file, "Host: %s ()\tPorts: %s\tStatus: Up\n", target, portsStr); err != nil {
		return fmt.Errorf("write grepable report: %w", err)
	}
	if _, err := fmt.Fprintf(file, "# tcpcat done -- 1 IP address scanned in %v\n", duration.Round(time.Millisecond)); err != nil {
		return fmt.Errorf("write grepable report: %w", err)
	}

	return nil
}
