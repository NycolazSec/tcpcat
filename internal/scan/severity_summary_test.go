package scan

import (
	"reflect"
	"testing"

	"tcpcat/internal/vuln"
)

func TestSummarizeSeverity(t *testing.T) {
	results := []TargetResult{
		{IP: "10.0.0.1", Vulnerabilities: []vuln.Vulnerability{
			{ID: "CVE-1", Severity: "critical"},
			{ID: "CVE-2", Severity: "high"},
		}},
		{IP: "10.0.0.2", Vulnerabilities: []vuln.Vulnerability{
			{ID: "CVE-3", Severity: "critical"},
		}},
		{IP: "10.0.0.1", Vulnerabilities: []vuln.Vulnerability{
			// Same host, second port -- must not double-count the host in
			// "critical"'s host list even though it appears in two results.
			{ID: "CVE-4", Severity: "critical"},
		}},
	}

	got := SummarizeSeverity(results)

	want := []SeveritySummaryEntry{
		// Count is every vulnerability instance (3: CVE-1, CVE-3, CVE-4);
		// Hosts is the deduplicated host list (2: 10.0.0.1 appears twice).
		{Severity: "critical", Count: 3, Hosts: []string{"10.0.0.1", "10.0.0.2"}},
		{Severity: "high", Count: 1, Hosts: []string{"10.0.0.1"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SummarizeSeverity() = %+v, want %+v", got, want)
	}
}

func TestSummarizeSeverityOmitsEmptyTiers(t *testing.T) {
	got := SummarizeSeverity([]TargetResult{{IP: "10.0.0.1", Vulnerabilities: []vuln.Vulnerability{{ID: "CVE-1", Severity: "low"}}}})
	if len(got) != 1 || got[0].Severity != "low" {
		t.Errorf("SummarizeSeverity() = %+v, want exactly one \"low\" entry", got)
	}
}

func TestSummarizeSeverityNoVulnerabilities(t *testing.T) {
	got := SummarizeSeverity([]TargetResult{{IP: "10.0.0.1", State: StateOpen}})
	if len(got) != 0 {
		t.Errorf("SummarizeSeverity() = %+v, want empty", got)
	}
}
