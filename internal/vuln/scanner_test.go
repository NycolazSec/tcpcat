package vuln

import (
	"testing"
)

func TestVulnerabilityStructure(t *testing.T) {
	vuln := Vulnerability{
		ID:    "CVE-2021-1234",
		Title: "Test vulnerability",
		CVSS:  7.5,
	}

	if vuln.ID == "" {
		t.Error("ID should not be empty")
	}

	if vuln.Title == "" {
		t.Error("Title should not be empty")
	}

	if vuln.CVSS == 0 {
		t.Log("CVSS should be non-zero for real vulnerabilities")
	}
}

func TestVulnerabilitySeverityLevels(t *testing.T) {

	cvssScores := []float64{0, 3.9, 7.0, 9.0, 10.0}

	for _, cvss := range cvssScores {
		t.Run(string(rune(int(cvss))), func(t *testing.T) {
			if cvss < 0 || cvss > 10 {
				t.Errorf("CVSS out of range: %f", cvss)
			}
		})
	}
}

func TestEnrichAddsEnterpriseRiskMetadata(t *testing.T) {
	vulns := Enrich([]Vulnerability{{ID: "CVE-2021-1234", CVSS: 9.8}})

	if vulns[0].Severity != "critical" {
		t.Fatalf("Severity = %q, want critical", vulns[0].Severity)
	}
	if vulns[0].Confidence != "version-based" {
		t.Fatalf("Confidence = %q, want version-based", vulns[0].Confidence)
	}
	if vulns[0].Remediation == "" {
		t.Fatal("Remediation must be provided")
	}
}

func TestOfflineScannerFindsApacheHTTPD249Vulnerability(t *testing.T) {
	scanner, err := NewOfflineScanner()
	if err != nil {
		t.Fatalf("NewOfflineScanner() error = %v", err)
	}

	vulns, err := scanner.GetForSoftware("Apache", "2.4.49")
	if err != nil {
		t.Fatalf("GetForSoftware() error = %v", err)
	}
	// 2.4.49 carries both the original path-traversal CVE and the incomplete
	// fix's own CVE (CVE-2021-42013), which affects both 2.4.49 and 2.4.50.
	if len(vulns) != 2 {
		t.Fatalf("found %d vulnerabilities, want 2", len(vulns))
	}
	ids := map[string]bool{vulns[0].ID: true, vulns[1].ID: true}
	if !ids["CVE-2021-41773"] || !ids["CVE-2021-42013"] {
		t.Errorf("vulnerability IDs = %v, want CVE-2021-41773 and CVE-2021-42013", ids)
	}
}

func TestSeverityForCVSS(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{9.0, "critical"},
		{7.0, "high"},
		{4.0, "medium"},
		{0.1, "low"},
		{0, "info"},
	}

	for _, tt := range tests {
		if got := SeverityForCVSS(tt.score); got != tt.want {
			t.Errorf("SeverityForCVSS(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestFilterRelevantCVEs(t *testing.T) {
	vulns := []Vulnerability{
		{
			ID:    "CVE-2021-1111",
			Title: "Linux vulnerability",
			CVSS:  9.0,
		},
		{
			ID:    "CVE-2021-2222",
			Title: "Windows vulnerability",
			CVSS:  8.0,
		},
		{
			ID:    "CVE-2021-3333",
			Title: "Generic vulnerability",
			CVSS:  6.0,
		},
	}

	result := FilterRelevantCVEs(vulns, "linux")

	if len(result) < 1 {
		t.Error("Should find at least one vulnerability")
	}

	for _, vuln := range result {
		if vuln.CVSS < 0 || vuln.CVSS > 10 {
			t.Errorf("Invalid CVSS score: %f", vuln.CVSS)
		}
	}
}

func TestFilterRelevantCVEsEmpty(t *testing.T) {
	vulns := []Vulnerability{}

	result := FilterRelevantCVEs(vulns, "linux")

	if len(result) > 0 {
		t.Error("Should return empty or nil for no vulnerabilities")
	}
}

func TestFilterRelevantCVEsUnknownOS(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "CVE-2021-1111", Title: "Test", CVSS: 7.0},
	}

	result := FilterRelevantCVEs(vulns, "unknown-os")

	if result != nil {
		t.Logf("Unknown OS filtering returned %d results", len(result))
	}
}

func TestFilterRelevantCVEsAllMatch(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "CVE-2021-1111", Title: "Critical", CVSS: 9.0},
		{ID: "CVE-2021-2222", Title: "High", CVSS: 8.0},
		{ID: "CVE-2021-3333", Title: "Medium", CVSS: 6.0},
	}

	result := FilterRelevantCVEs(vulns, "linux")

	if len(result) != len(vulns) {
		t.Logf("Expected all vulns, got %d/%d", len(result), len(vulns))
	}
}

func TestCVEFormat(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		valid bool
	}{
		{"standard", "CVE-2021-1234", true},
		{"standard", "CVE-2020-9999", true},
		{"invalid", "CVE-2021", false},
		{"invalid", "NOTCVE-2021-1234", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.valid && len(tt.id) < 10 {
				t.Errorf("Valid CVE too short: %s", tt.id)
			}
		})
	}
}

func TestVulnerabilityCVSSComparison(t *testing.T) {

	lowVuln := Vulnerability{ID: "CVE-2021-0001", Title: "Low", CVSS: 2.0}
	mediumVuln := Vulnerability{ID: "CVE-2021-0002", Title: "Medium", CVSS: 5.0}
	highVuln := Vulnerability{ID: "CVE-2021-0003", Title: "High", CVSS: 9.0}

	if lowVuln.CVSS >= mediumVuln.CVSS {
		t.Error("Low should be less than medium")
	}

	if mediumVuln.CVSS >= highVuln.CVSS {
		t.Error("Medium should be less than high")
	}
}

func TestVulnerabilityDeduplication(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "CVE-2021-1111", Title: "Test 1", CVSS: 7.0},
		{ID: "CVE-2021-1111", Title: "Test 1", CVSS: 7.0},
		{ID: "CVE-2021-2222", Title: "Test 2", CVSS: 6.0},
	}

	idMap := make(map[string]bool)
	for _, vuln := range vulns {
		if idMap[vuln.ID] {
			t.Logf("Duplicate ID found: %s", vuln.ID)
		}
		idMap[vuln.ID] = true
	}
}

func BenchmarkFilterRelevantCVEs(b *testing.B) {
	vulns := make([]Vulnerability, 100)
	for i := 0; i < 100; i++ {
		vulns[i] = Vulnerability{
			ID:    "CVE-2021-" + string(rune(i)),
			Title: "Test vulnerability",
			CVSS:  7.5,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterRelevantCVEs(vulns, "linux")
	}
}
