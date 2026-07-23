// internal/output/grepable.go
package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	"tcpcat/internal/scan"
)

// ExportGrepable écrit les résultats au format grepable (-oG).
func ExportGrepable(filePath string, target string, results []scan.TargetResult, duration time.Duration) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("impossible de créer le fichier %s: %w", filePath, err)
	}
	defer file.Close()

	fmt.Fprintf(file, "# tcpcat 5.0 scan report for %s\n", target)

	var portEntries []string
	for _, r := range results {
		svc := r.Service
		if svc == "" {
			svc = "unknown"
		}
		portEntries = append(portEntries, fmt.Sprintf("%d/%s/%s//%s///", r.Port, strings.ToLower(r.State), "tcp", svc))
	}

	portsStr := strings.Join(portEntries, ", ")
	fmt.Fprintf(file, "Host: %s ()\tPorts: %s\tStatus: Up\n", target, portsStr)
	fmt.Fprintf(file, "# tcpcat done -- 1 IP address scanned in %v\n", duration.Round(time.Millisecond))

	return nil
}