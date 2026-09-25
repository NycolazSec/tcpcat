package vuln

import (
	"regexp"
	"strings"
)

type Vulnerability struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
	Confidence  string  `json:"confidence,omitempty"`
	// Applicability flags a CVE whose *title* names a precondition this
	// scan has no evidence is met -- a different OS entirely ("... on
	// Windows"), or an optional component tcpcat never probes for (wsrep/
	// Galera replication). Empty means nothing suspicious was found in the
	// title (the common case), not a confirmed "definitely applicable".
	// Never removes the entry: it stays in Vulnerabilities/JSON exactly as
	// found, just not counted toward this host's headline risk (see
	// cmd/tcpcat/main.go's RiskSeverity selection).
	Applicability string `json:"applicability,omitempty"`
}

type Scanner interface {
	GetForSoftware(software, version string) ([]Vulnerability, error)
	SourceName() string
}

func Enrich(vulns []Vulnerability) []Vulnerability {
	for i := range vulns {
		vulns[i].Severity = SeverityForCVSS(vulns[i].CVSS)
		vulns[i].Remediation = "Update the affected software to a vendor-supported version and verify the remediation."
		// A caller may have already tagged this entry (e.g. the distro-aware
		// lookup in cmd/tcpcat/main.go marking one "potential (upstream
		// version match)" when only an upstream, not a distro-backport,
		// match was confirmed) -- don't clobber that with the generic default.
		if vulns[i].Confidence == "" {
			vulns[i].Confidence = "version-based"
		}
	}
	return vulns
}

// osMentionPattern finds an OS named directly in a CVE title -- some
// upstream advisories (Oracle MySQL's own bulletins, notably) describe a
// vulnerability that only actually applies to one specific platform, and
// say so in prose rather than through any structured field OSV exposes.
var osMentionPattern = regexp.MustCompile(`(?i)\b(Windows|macOS|Mac OS X?|Darwin|FreeBSD)\b`)

// componentMentionPattern finds a mention of an optional, non-default
// component tcpcat has no way to confirm is even installed or enabled --
// wsrep/Galera multi-master replication is the common case for MariaDB.
// No trailing \b: real titles routinely use it as an identifier prefix
// with an immediately-following underscore ("wsrep_notify_cmd",
// "wsrep_sst_*"), which is a word character and so leaves no boundary for
// \b to match right after "wsrep".
var componentMentionPattern = regexp.MustCompile(`(?i)\b(wsrep|galera)`)

// osFamily normalizes both a title's OS mention and tcpcat's own detected
// OS name (see internal/service/engine.go's osRegexps) to the same small
// vocabulary, so "Mac OS X" in a title and "macos" from detection compare
// equal, and any Linux distribution detection (ubuntu/debian/alpine/...)
// groups under "linux".
func osFamily(name string) string {
	switch strings.ToLower(name) {
	case "windows":
		return "windows"
	case "macos", "mac os", "mac os x", "darwin":
		return "macos"
	case "freebsd":
		return "freebsd"
	case "ubuntu", "debian", "alpine", "centos", "amazon", "linux":
		return "linux"
	default:
		return ""
	}
}

// AnnotateApplicability sets Applicability on any entry whose title names
// a precondition this scan has no evidence is met (see the field's doc
// comment). detectedOS is tcpcat's own OS guess (r.OS, "unknown" or ""
// when it has none) -- an OS mention is only flagged when detectedOS is
// actually known and names a *different* family, so an unknown-OS host
// never has entries incorrectly downgraded for lack of information.
func AnnotateApplicability(vulns []Vulnerability, detectedOS string) []Vulnerability {
	detectedFamily := osFamily(detectedOS)
	for i := range vulns {
		if m := osMentionPattern.FindStringSubmatch(vulns[i].Title); m != nil {
			mentionedFamily := osFamily(m[1])
			if detectedFamily != "" && mentionedFamily != "" && mentionedFamily != detectedFamily {
				vulns[i].Applicability = "not_applicable_os:" + mentionedFamily
				continue
			}
		}
		if m := componentMentionPattern.FindStringSubmatch(vulns[i].Title); m != nil {
			vulns[i].Applicability = "requires_component:" + strings.ToLower(m[1])
		}
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
