package vuln

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const vulnersAPIEndpoint = "https://vulners.com/api/v3/burp/softwareVulnerabilities"

type VulnersScanner struct {
	apiKey     string
	httpClient *http.Client
}

func NewVulnersScanner(apiKey string) (*VulnersScanner, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("la clé API Vulners est requise")
	}
	return &VulnersScanner{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

type vulnersRequest struct {
	APIKey   string `json:"apiKey"`
	Software string `json:"software"`
	Version  string `json:"version"`
	Type     string `json:"type"`
}

type vulnersResponse struct {
	Result string `json:"result"`
	Data   struct {
		Search []struct {
			Source json.RawMessage `json:"_source"`
		} `json:"search"`
	} `json:"data"`
}

type vulnersSource struct {
	Title string `json:"title"`
	ID    string `json:"id"`
	CVSS  struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
}

func (s *VulnersScanner) GetForSoftware(software, version string) ([]Vulnerability, error) {
	software = strings.ToLower(software)

	reqBody := vulnersRequest{
		APIKey:   s.apiKey,
		Software: software,
		Version:  version,
		Type:     "software",
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("échec de la sérialisation de la requête Vulners: %w", err)
	}

	resp, err := s.httpClient.Post(vulnersAPIEndpoint, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("échec de l'appel à l'API Vulners: %w", err)
	}
	defer resp.Body.Close()

	var vulnersResp vulnersResponse
	if err := json.NewDecoder(resp.Body).Decode(&vulnersResp); err != nil {
		return nil, fmt.Errorf("échec du décodage de la réponse Vulners: %w", err)
	}

	if vulnersResp.Result != "OK" {
		return nil, fmt.Errorf("l'API Vulners a retourné une erreur: %s", vulnersResp.Result)
	}

	var vulnerabilities []Vulnerability
	for _, item := range vulnersResp.Data.Search {
		var sourceData vulnersSource
		if err := json.Unmarshal(item.Source, &sourceData); err == nil && sourceData.ID != "" {
			vulnerabilities = append(vulnerabilities, Vulnerability{ID: sourceData.ID, Title: sourceData.Title, CVSS: sourceData.CVSS.Score})
		}
	}

	return vulnerabilities, nil
}

func (s *VulnersScanner) SourceName() string {
	return "Vulners API"
}
