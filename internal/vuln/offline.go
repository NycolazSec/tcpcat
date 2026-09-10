package vuln

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const offlineDBJSON = `{
  "apache": {
    "2.4.49": [
      {
        "id": "CVE-2021-41773",
        "title": "Path traversal and file disclosure in Apache HTTP Server 2.4.49.",
        "cvss": 7.5
      },
      {
        "id": "CVE-2021-42013",
        "title": "Incomplete fix for CVE-2021-41773 allows path traversal and remote code execution.",
        "cvss": 9.8
      }
    ],
    "2.4.50": [
      {
        "id": "CVE-2021-42013",
        "title": "Incomplete fix for CVE-2021-41773 allows path traversal and remote code execution.",
        "cvss": 9.8
      }
    ],
    "2.4.38": [
      {
        "id": "CVE-2019-0211",
        "title": "Local privilege escalation via unprivileged child process code execution (scoreboard).",
        "cvss": 7.8
      }
    ],
    "2.4.26": [
      {
        "id": "CVE-2017-9798",
        "title": "Optionsbleed: uninitialized/freed memory disclosure via the OPTIONS method.",
        "cvss": 5.9
      }
    ]
  },
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
    ],
    "1.20.0": [
      {
        "id": "CVE-2021-23017",
        "title": "Off-by-one heap write in the DNS resolver allows cache poisoning or code execution.",
        "cvss": 9.8
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
    ],
    "7.7p1": [
      {
        "id": "CVE-2018-15473",
        "title": "Username enumeration via a crafted authentication request.",
        "cvss": 5.3
      }
    ],
    "9.3p1": [
      {
        "id": "CVE-2023-38408",
        "title": "Remote code execution via forwarded ssh-agent and a crafted PKCS#11 provider path.",
        "cvss": 9.8
      }
    ],
    "9.6p1": [
      {
        "id": "CVE-2024-6387",
        "title": "regreSSHion: signal handler race condition allows unauthenticated remote code execution.",
        "cvss": 8.1
      }
    ]
  },
  "redis": {
    "6.2.6": [
      {
        "id": "CVE-2022-24735",
        "title": "Lua sandbox escape allows execution of arbitrary Lua code loaded from a crafted script.",
        "cvss": 7.2
      },
      {
        "id": "CVE-2022-24736",
        "title": "Crafted Lua script triggers a NULL pointer dereference and denial of service.",
        "cvss": 7.5
      }
    ]
  },
  "mysql": {
    "5.5.23": [
      {
        "id": "CVE-2012-2122",
        "title": "Authentication bypass: repeated login attempts have a high probability of succeeding regardless of password on platforms where memcmp() can return values outside -128..127.",
        "cvss": 7.5
      }
    ]
  },
  "vsftpd": {
    "2.3.4": [
      {
        "id": "CVE-2011-2523",
        "title": "Backdoor in downloads of vsftpd 2.3.4 source: a crafted username containing \":)\" opens a shell on port 6200.",
        "cvss": 10.0
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

	if len(db) == 0 {
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
	if err := os.MkdirAll(dir, 0700); err != nil {
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

	if err := os.WriteFile(userDBPath, formattedData, 0600); err != nil {
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
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("could not create config directory: %w", err)
	}

	if err := os.WriteFile(userDBPath, formattedData, 0600); err != nil {
		return fmt.Errorf("could not write offline database: %w", err)
	}
	fmt.Printf("[*] Entry '%s %s' added/updated in offline database: %s\n", software, version, userDBPath)
	return nil
}
