package vuln

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const offlineDBJSON = `{
  "nginx": {
    "1.10.3": [
      {
        "id": "CVE-2017-7529",
        "title": "Integer overflow in nginx range filter module allows cache poisoning.",
        "cvss": 7.5
      },
      {
        "id": "CVE-2016-1247",
        "title": "Privilege escalation in nginx packages on Debian-based systems.",
        "cvss": 7.8
      }
    ]
  },
  "openssh": {
    "7.2p2": [
      {
        "id": "CVE-2016-10009",
        "title": "Untrusted search path vulnerability in ssh-agent.",
        "cvss": 5.0
      }
    ]
  }
}`

type OfflineScanner struct {
	db map[string]map[string][]Vulnerability
}

func NewOfflineScanner() (*OfflineScanner, error) {
	var dbData []byte

	userDBPath := getUserOfflineDBPath()
	if userDBPath != "" {
		if data, err := os.ReadFile(userDBPath); err == nil && len(data) > 0 {
			fmt.Printf("[*] Loading offline vulnerability database from: %s\n", userDBPath)
			dbData = data
		}
	}

	if dbData == nil {
		dbData = []byte(offlineDBJSON)
	}

	var db map[string]map[string][]Vulnerability
	if err := json.Unmarshal(dbData, &db); err != nil {
		return nil, fmt.Errorf("could not parse vulnerability database: %w", err)
	}

	if db == nil || len(db) == 0 {
		return nil, fmt.Errorf("loaded vulnerability database is empty or invalid")
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

func getUserOfflineDBPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(configDir, "tcpcat", "offline_db.json")
}

func UpdateOfflineDB(newData []byte) error {
	userDBPath := getUserOfflineDBPath()
	if userDBPath == "" {
		return fmt.Errorf("could not determine user database path")
	}

	dir := filepath.Dir(userDBPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("could not create config directory: %w", err)
	}

	var tempDB map[string]map[string][]Vulnerability
	if err := json.Unmarshal(newData, &tempDB); err != nil {
		return fmt.Errorf("provided data is not a valid database JSON: %w", err)
	}

	formattedData, err := json.MarshalIndent(tempDB, "", "  ")
	if err != nil {
		return fmt.Errorf("could not format JSON data: %w", err)
	}

	if err := os.WriteFile(userDBPath, formattedData, 0644); err != nil {
		return fmt.Errorf("could not write offline database: %w", err)
	}
	fmt.Printf("[*] Offline database successfully updated: %s\n", userDBPath)
	return nil
}

func GetEmbeddedOfflineDB() []byte {
	return []byte(offlineDBJSON)
}

func AddSoftwareToOfflineDB(software, version string, newVulns []Vulnerability) error {
	userDBPath := getUserOfflineDBPath()
	if userDBPath == "" {
		return fmt.Errorf("could not determine user database path")
	}

	var currentDB map[string]map[string][]Vulnerability
	if data, err := os.ReadFile(userDBPath); err == nil {
		if err := json.Unmarshal(data, &currentDB); err != nil {
			return fmt.Errorf("could not read existing database: %w", err)
		}
	} else {
		if err := json.Unmarshal([]byte(offlineDBJSON), &currentDB); err != nil {
			return fmt.Errorf("could not parse embedded database: %w", err)
		}
	}

	if currentDB == nil {
		currentDB = make(map[string]map[string][]Vulnerability)
	}

	software = strings.ToLower(software)
	if _, ok := currentDB[software]; !ok {
		currentDB[software] = make(map[string][]Vulnerability)
	}
	currentDB[software][version] = newVulns

	formattedData, err := json.MarshalIndent(currentDB, "", "  ")
	if err != nil {
		return fmt.Errorf("could not format JSON data: %w", err)
	}

	dir := filepath.Dir(userDBPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("could not create config directory: %w", err)
	}

	if err := os.WriteFile(userDBPath, formattedData, 0644); err != nil {
		return fmt.Errorf("could not write offline database: %w", err)
	}
	fmt.Printf("[*] Entry '%s %s' added/updated in offline database: %s\n", software, version, userDBPath)
	return nil
}
