package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NycolazSec/tcpcat/internal/scan"
	"github.com/NycolazSec/tcpcat/internal/vuln"
)

func TestExportHTML(t *testing.T) {
	results := []scan.TargetResult{
		{
			IP: "10.0.0.1", Port: 22, State: scan.StateOpen,
			Service: "openssh", Version: "6.6.1p1", OS: "ubuntu", LatencyMs: 12.3,
			Vulnerabilities: []vuln.Vulnerability{
				{ID: "CVE-2021-0001", CVSS: 9.8, Severity: "critical", KnownExploited: true, EPSS: 0.97, Title: "a serious bug"},
				// A hostile CVE title must not be able to inject markup.
				{ID: "CVE-2021-0002", CVSS: 5.0, Severity: "medium", Title: "<script>alert(1)</script>"},
			},
		},
		{IP: "10.0.0.1", Port: 81, State: scan.StateClosed, Service: "x"}, // excluded from report
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	if err := ExportHTML(path, "10.0.0.1", results, 1500*time.Millisecond); err != nil {
		t.Fatalf("ExportHTML: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	html := string(data)

	for _, want := range []string{
		"<!doctype html>", "10.0.0.1", "22/tcp", "openssh",
		"CVE-2021-0001", "CVE-2021-0002", "KEV", "EPSS 97.0%",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report missing %q", want)
		}
	}

	// The malicious title must be HTML-escaped, never present as a live tag.
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Errorf("hostile CVE title was not escaped -- report is XSS-injectable")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("expected the escaped form of the hostile title")
	}

	// A closed port must not appear in the report body.
	if strings.Contains(html, "81/tcp") {
		t.Errorf("closed port 81 should be excluded from the HTML report")
	}
}

func TestExportHTMLNoOpenPorts(t *testing.T) {
	results := []scan.TargetResult{
		{IP: "10.0.0.1", Port: 80, State: scan.StateClosed},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.html")
	if err := ExportHTML(path, "10.0.0.1", results, time.Second); err != nil {
		t.Fatalf("ExportHTML: %v", err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "No open ports were found") {
		t.Errorf("expected an empty-state message when there are no open ports")
	}
}
