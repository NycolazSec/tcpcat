package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

const osvApiUrl = "https://api.osv.dev/v1/query"

// cveIDPattern extracts a canonical CVE identifier out of an OSV entry.
// OSV re-publishes the same underlying CVE under a different ID per vendor
// feed -- "ALPINE-CVE-2016-10009", "BIT-apache-2020-11985" (whose alias
// list carries "CVE-2020-11985" instead), "DEBIAN-CVE-2000-0992", and so
// on -- so a raw query for one piece of software routinely comes back with
// the same handful of real vulnerabilities restated dozens of times under
// different namespaces. canonicalCVEID below normalizes each entry to its
// underlying CVE ID (falling back to the OSV-native ID when there isn't
// one), which both lets duplicates collapse into a single row and makes
// FilterRelevantCVEs' plain "CVE-" prefix check actually match again.
var cveIDPattern = regexp.MustCompile(`CVE-\d{4}-\d+`)

// canonicalCVEID returns v's underlying CVE identifier: first from a
// pattern match against the OSV-native ID itself (covers vendor feeds like
// Alpine/Debian that fold the CVE straight into their own ID), then from
// v's alias list (covers feeds like OSV's own "BIT-" entries that carry it
// separately), and finally the raw ID unchanged when neither has one (a
// vendor errata with no CVE mapping at all, e.g. an RHSA/MGASA bulletin).
func canonicalCVEID(v osvVulnerability) string {
	if m := cveIDPattern.FindString(v.ID); m != "" {
		return m
	}
	for _, alias := range v.Aliases {
		if m := cveIDPattern.FindString(alias); m != "" {
			return m
		}
	}
	return v.ID
}

type OSVScanner struct {
	client *http.Client
}

func NewOSVScanner() *OSVScanner {
	return &OSVScanner{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *OSVScanner) SourceName() string {
	return "OSV API"
}

func (s *OSVScanner) GetForSoftware(software, version string) ([]Vulnerability, error) {
	if software == "" || version == "" {
		return nil, nil
	}
	return s.query(osvPackage{Name: software}, version)
}

// GetForDistroPackage runs an ecosystem-scoped query (e.g. "Debian:12",
// "Ubuntu:24.04" -- see internal/vuln/distro.go's DetectDistroPackage)
// instead of an upstream-only one, so a distro's own backported fix (which
// routinely lands well before, or entirely without, a matching upstream
// version bump) is reflected instead of missed.
func (s *OSVScanner) GetForDistroPackage(pkg DistroPackage) ([]Vulnerability, error) {
	if pkg.Name == "" || pkg.Version == "" || pkg.Ecosystem == "" {
		return nil, nil
	}
	return s.query(osvPackage{Name: pkg.Name, Ecosystem: pkg.Ecosystem}, pkg.Version)
}

func (s *OSVScanner) query(pkg osvPackage, version string) ([]Vulnerability, error) {
	query := osvQuery{
		Version: version,
		Package: pkg,
	}

	body, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("osv: could not marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", osvApiUrl, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv: could not create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("osv: api returned non-200 status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("osv: could not decode response: %w", err)
	}

	if len(osvResp.Vulns) == 0 {
		return nil, nil
	}

	// seen maps a canonical CVE ID to its row's index in vulnerabilities,
	// so the same underlying CVE restated under several vendor feeds (see
	// canonicalCVEID) collapses into one row instead of one per feed.
	seen := make(map[string]int)
	var vulnerabilities []Vulnerability
	for _, v := range osvResp.Vulns {
		if !IsVersionAffected(version, v.Affected) {
			continue
		}

		title := v.Summary
		if title == "" {
			title = v.Details
		}
		if len(title) > 100 {
			title = title[:97] + "..."
		}
		cvss := extractCVSSScore(v.Severity, v.DatabaseSpecific, v.Affected)
		id := canonicalCVEID(v)

		if idx, ok := seen[id]; ok {
			if cvss > vulnerabilities[idx].CVSS {
				vulnerabilities[idx].CVSS = cvss
			}
			if vulnerabilities[idx].Title == "" {
				vulnerabilities[idx].Title = title
			}
			continue
		}

		seen[id] = len(vulnerabilities)
		vulnerabilities = append(vulnerabilities, Vulnerability{ID: id, Title: title, CVSS: cvss})
	}

	return vulnerabilities, nil
}

type osvQuery struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}
type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem,omitempty"`
}
type osvResponse struct {
	Vulns []osvVulnerability `json:"vulns"`
}
type osvVulnerability struct {
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases"`
	Summary          string          `json:"summary"`
	Details          string          `json:"details"`
	Severity         []osvSeverity   `json:"severity"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
	Affected         []osvAffected   `json:"affected"`
}
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package  osvPackage    `json:"package"`
	Ranges   []osvRange    `json:"ranges"`
	Versions []string      `json:"versions,omitempty"`
	Severity []osvSeverity `json:"severity"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvDatabaseSpecific struct {
	CVSS *struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
}

// extractCVSSScore reads a numeric CVSS score for a vulnerability out of
// whichever of the several places an OSV feed might have put it. The
// top-level severity/database_specific fields cover most feeds (GHSA,
// Alpine, ...), but the Bitnami vulndb import ("BIT-*" IDs -- a large share
// of results for anything installed as a prebuilt package, e.g. Apache)
// carries its CVSS_V3 vector only under affected[].severity instead, so
// that is checked last as a fallback rather than left unread.
func extractCVSSScore(severities []osvSeverity, dbSpecific json.RawMessage, affected []osvAffected) float64 {
	if len(dbSpecific) > 4 {
		var specificData osvDatabaseSpecific
		if err := json.Unmarshal(dbSpecific, &specificData); err == nil {
			if specificData.CVSS != nil && specificData.CVSS.Score > 0 {
				return specificData.CVSS.Score
			}
		}
	}

	if score := maxCVSSV3(severities); score > 0 {
		return score
	}

	for _, a := range affected {
		if score := maxCVSSV3(a.Severity); score > 0 {
			return score
		}
	}

	return 0
}

func maxCVSSV3(severities []osvSeverity) float64 {
	var maxScore = 0.0
	for _, s := range severities {
		if s.Type == "CVSS_V3" && s.Score != "" {
			score := ParseAndCalculateCVSSv3(s.Score)
			if score > maxScore {
				maxScore = score
			}
		}
	}
	return maxScore
}
