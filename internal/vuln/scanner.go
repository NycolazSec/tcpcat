package vuln

import "strings"

type Vulnerability struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
	Confidence  string  `json:"confidence,omitempty"`
}

type Scanner interface {
	GetForSoftware(software, version string) ([]Vulnerability, error)
	SourceName() string
}

func Enrich(vulns []Vulnerability) []Vulnerability {
	for i := range vulns {
		vulns[i].Severity = SeverityForCVSS(vulns[i].CVSS)
		vulns[i].Remediation = "Update the affected software to a vendor-supported version and verify the remediation."
		vulns[i].Confidence = "version-based"
	}
	return vulns
}

func SeverityForCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

func FilterRelevantCVEs(vulns []Vulnerability, detectedOS string) []Vulnerability {
	if detectedOS == "unknown" {
		var filtered []Vulnerability
		for _, v := range vulns {
			if v.CVSS >= 5.0 {
				filtered = append(filtered, v)
			}
		}
		return filtered
	}

	osPrefixes := map[string][]string{
		"ubuntu": {"UBUNTU-"},
		"debian": {"DEBIAN-"},
		"alpine": {"ALPINE-"},
		"amazon": {"ALSA-", "AZL-"},
	}

	relevantPrefixes := osPrefixes[detectedOS]
	relevantPrefixes = append(relevantPrefixes, "CVE-", "GHSA-")

	var filteredVulns []Vulnerability
	for _, vuln := range vulns {
		isRelevant := false
		for _, prefix := range relevantPrefixes {
			if strings.HasPrefix(vuln.ID, prefix) {
				isRelevant = true
				break
			}
		}

		if isRelevant {
			filteredVulns = append(filteredVulns, vuln)
		}
	}
	return filteredVulns
}
