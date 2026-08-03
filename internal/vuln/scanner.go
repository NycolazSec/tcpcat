package vuln

import "strings"

type Vulnerability struct {
	ID    string  `json:"id"`
	Title string  `json:"title"`
	CVSS  float64 `json:"cvss"`
}

type Scanner interface {
	GetForSoftware(software, version string) ([]Vulnerability, error)
	SourceName() string
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
