package compare

import (
	"testing"

	"tcpcat/internal/scan"
	"tcpcat/internal/vuln"
)

func TestCompareReportsNewExposureChanges(t *testing.T) {
	baseline := []scan.TargetResult{{IP: "127.0.0.1", Port: 80, State: scan.StateOpen, Service: "apache", Version: "2.4.48"}}
	current := []scan.TargetResult{
		{IP: "127.0.0.1", Port: 80, State: scan.StateOpen, Service: "apache", Version: "2.4.49", Vulnerabilities: []vuln.Vulnerability{{ID: "CVE-2021-41773"}}},
		{IP: "127.0.0.1", Port: 443, State: scan.StateOpen},
	}

	report := Compare(current, baseline)
	if len(report.NewOpenPorts) != 1 || report.NewOpenPorts[0].Port != 443 {
		t.Fatalf("new open ports = %+v, want port 443", report.NewOpenPorts)
	}
	if len(report.ServiceChanges) != 1 || report.ServiceChanges[0].NewVersion != "2.4.49" {
		t.Fatalf("service changes = %+v", report.ServiceChanges)
	}
	if len(report.NewVulnerabilities) != 1 || report.NewVulnerabilities[0].NewVulnerability != "CVE-2021-41773" {
		t.Fatalf("new vulnerabilities = %+v", report.NewVulnerabilities)
	}
}
