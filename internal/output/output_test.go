package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tcpcat/internal/scan"
	"tcpcat/internal/vuln"
)

func TestExportAuditJSONLWritesOneRecord(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "audit.jsonl")
	options := AuditOptions{Profile: "safe-production", RateLimit: 300, Timing: 2}
	if err := ExportAuditJSONL(filePath, "127.0.0.1", options, nil, time.Second); err != nil {
		t.Fatalf("ExportAuditJSONL() error = %v", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil || !strings.HasSuffix(string(data), "\n") || !strings.Contains(string(data), "scan_id") || !strings.Contains(string(data), "safe-production") {
		t.Fatalf("invalid audit record: %q, error = %v", data, err)
	}
}

func TestExportSARIFIncludesCVEs(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.sarif")
	results := []scan.TargetResult{{IP: "127.0.0.1", Port: 8080, State: scan.StateOpen, Vulnerabilities: []vuln.Vulnerability{{ID: "CVE-2021-41773", Title: "Apache issue", CVSS: 7.5}}}}
	if err := ExportSARIF(filePath, results); err != nil {
		t.Fatalf("ExportSARIF() error = %v", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil || !strings.Contains(string(data), `"version": "2.1.0"`) || !strings.Contains(string(data), "CVE-2021-41773") {
		t.Fatalf("invalid SARIF report: %q, error = %v", data, err)
	}
}
