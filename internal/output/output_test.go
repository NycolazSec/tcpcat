package output

import (
	"encoding/json"
	"encoding/xml"
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

func sampleResults() []scan.TargetResult {
	return []scan.TargetResult{
		{Port: 22, State: scan.StateOpen, Service: "ssh", Banner: "OpenSSH_9.6"},
		{Port: 80, State: scan.StateClosed, Service: "http"},
	}
}

func checkExportedFilePerm(t *testing.T, filePath string) {
	t.Helper()
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat exported file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestExportJSON(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.json")
	if err := ExportJSON(filePath, "127.0.0.1", sampleResults(), 2*time.Second); err != nil {
		t.Fatalf("ExportJSON() error = %v", err)
	}
	checkExportedFilePerm(t, filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("exported file is not valid JSON: %v", err)
	}
	if report.Target != "127.0.0.1" || len(report.Results) != 2 {
		t.Errorf("got %+v, want target=127.0.0.1 with 2 results", report)
	}
}

func TestExportGrepable(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.gnmap")
	if err := ExportGrepable(filePath, "127.0.0.1", sampleResults(), 2*time.Second); err != nil {
		t.Fatalf("ExportGrepable() error = %v", err)
	}
	checkExportedFilePerm(t, filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	content := string(data)
	for _, want := range []string{"Host: 127.0.0.1", "22/open/tcp//ssh///", "80/closed/tcp//http///"} {
		if !strings.Contains(content, want) {
			t.Errorf("grepable report missing %q:\n%s", want, content)
		}
	}
}

func TestExportNormal(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.txt")
	if err := ExportNormal(filePath, "127.0.0.1", sampleResults(), 2*time.Second); err != nil {
		t.Fatalf("ExportNormal() error = %v", err)
	}
	checkExportedFilePerm(t, filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	content := string(data)
	for _, want := range []string{"PORT", "STATE", "22/tcp", "ssh", "OpenSSH_9.6", "80/tcp"} {
		if !strings.Contains(content, want) {
			t.Errorf("normal report missing %q:\n%s", want, content)
		}
	}
}

func TestExportXML(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.xml")
	if err := ExportXML(filePath, "127.0.0.1", sampleResults(), 2*time.Second); err != nil {
		t.Fatalf("ExportXML() error = %v", err)
	}
	checkExportedFilePerm(t, filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	var report XMLReport
	if err := xml.Unmarshal(data, &report); err != nil {
		t.Fatalf("exported file is not valid XML: %v", err)
	}
	if report.Target != "127.0.0.1" || len(report.Host.Ports) != 2 {
		t.Errorf("got %+v, want target=127.0.0.1 with 2 ports", report)
	}
	if report.Host.Ports[0].State.State != "open" {
		t.Errorf("port state = %q, want lowercased 'open'", report.Host.Ports[0].State.State)
	}
}

func TestExportScriptKiddie(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.1337")
	if err := ExportScriptKiddie(filePath, "127.0.0.1", sampleResults(), 2*time.Second); err != nil {
		t.Fatalf("ExportScriptKiddie() error = %v", err)
	}
	checkExportedFilePerm(t, filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	// toLeet replaces letters with digits, so the leetspeak port line for
	// port 22 ("Port 22/tcp is open (ssh)") should no longer read plainly.
	if strings.Contains(string(data), "Port 22/tcp is open") {
		t.Errorf("expected leetspeak transformation, got plain text:\n%s", data)
	}
}

func TestToLeet(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"leet", "l337"},
		{"LEET", "L337"},
		{"Attack", "4774ck"},
		{"1234", "1234"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := toLeet(tt.in); got != tt.want {
				t.Errorf("toLeet(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
