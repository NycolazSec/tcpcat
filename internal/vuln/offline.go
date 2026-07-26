package vuln

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

var offlineDBFS embed.FS

type OfflineScanner struct {
	db map[string]map[string][]Vulnerability
}

func NewOfflineScanner() (*OfflineScanner, error) {
	data, err := offlineDBFS.ReadFile("offline_db.json")
	if err != nil {
		return nil, fmt.Errorf("impossible de lire la base de données de vulnérabilités embarquée: %w", err)
	}

	var db map[string]map[string][]Vulnerability
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("impossible de parser la base de données de vulnérabilités: %w", err)
	}

	return &OfflineScanner{db: db}, nil
}

func (s *OfflineScanner) GetForSoftware(software, version string) ([]Vulnerability, error) {
	software = strings.ToLower(software)
	if versions, ok := s.db[software]; ok {
		if vulns, ok := versions[version]; ok {
			return vulns, nil
		}
	}
	return nil, nil
}

func (s *OfflineScanner) SourceName() string {
	return "Offline DB"
}
