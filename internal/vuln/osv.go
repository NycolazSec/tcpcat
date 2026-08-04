package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const osvApiUrl = "https://api.osv.dev/v1/query"

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
		return nil, nil // Not enough info to query
	}

	query := osvQuery{
		Version: version,
		Package: osvPackage{Name: software},
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("osv: api returned non-200 status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("osv: could not decode response: %w", err)
	}

	if osvResp.Vulns == nil || len(osvResp.Vulns) == 0 {
		return nil, nil // No vulnerabilities found
	}

	var vulnerabilities []Vulnerability
	for _, v := range osvResp.Vulns {
		vuln := Vulnerability{
			ID:    v.ID,
			Title: v.Summary,
		}
		if vuln.Title == "" {
			vuln.Title = v.Details
		}
		if len(vuln.Title) > 100 {
			vuln.Title = vuln.Title[:97] + "..."
		}

		// Check if the target version is actually affected by this vulnerability
		if !IsVersionAffected(version, v.Affected) {
			continue
		}

		vuln.CVSS = extractCVSSScore(v.Severity, v.DatabaseSpecific)
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

type osvQuery struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}
type osvPackage struct {
	Name string `json:"name"`
}
type osvResponse struct {
	Vulns []osvVulnerability `json:"vulns"`
}
type osvVulnerability struct {
	ID               string          `json:"id"`
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
	Package  osvPackage `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions,omitempty"`
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

func extractCVSSScore(severities []osvSeverity, dbSpecific json.RawMessage) float64 {
	if len(dbSpecific) > 4 { // Check for non-empty JSON (`null` is 4 bytes)
		var specificData osvDatabaseSpecific
		if err := json.Unmarshal(dbSpecific, &specificData); err == nil {
			if specificData.CVSS != nil && specificData.CVSS.Score > 0 {
				return specificData.CVSS.Score
			}
		}
	}

	var maxScore float64 = 0.0
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
