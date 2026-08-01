package vuln

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// offlineDBJSON contains the embedded vulnerability database as a raw string.
// This avoids file system dependencies and ensures the DB is always available.
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

	// 1. Essayer de charger une base de données externe fournie par l'utilisateur.
	userDBPath := getUserOfflineDBPath()
	if userDBPath != "" {
		if data, err := os.ReadFile(userDBPath); err == nil && len(data) > 0 {
			fmt.Printf("[*] Chargement de la base de données de vulnérabilités hors ligne depuis: %s\n", userDBPath)
			dbData = data
		}
	}

	// 2. Si aucune base de données externe n'est trouvée, utiliser la base de données embarquée.
	if dbData == nil {
		dbData = []byte(offlineDBJSON)
	}

	var db map[string]map[string][]Vulnerability
	if err := json.Unmarshal(dbData, &db); err != nil {
		return nil, fmt.Errorf("impossible de parser la base de données de vulnérabilités: %w", err)
	}

	// Valider la structure de la base de données chargée
	if db == nil || len(db) == 0 {
		return nil, fmt.Errorf("la base de données de vulnérabilités chargée est vide ou invalide")
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

// getUserOfflineDBPath retourne le chemin attendu pour la base de données hors ligne de l'utilisateur.
func getUserOfflineDBPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(configDir, "tcpcat", "offline_db.json")
}

// UpdateOfflineDB permet de mettre à jour la base de données hors ligne de l'utilisateur.
func UpdateOfflineDB(newData []byte) error {
	userDBPath := getUserOfflineDBPath()
	if userDBPath == "" {
		return fmt.Errorf("impossible de déterminer le chemin de la base de données utilisateur")
	}

	// Assurez-vous que le répertoire existe
	dir := filepath.Dir(userDBPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("impossible de créer le répertoire de configuration: %w", err)
	}

	// Valider le JSON avant d'écrire
	var tempDB map[string]map[string][]Vulnerability
	if err := json.Unmarshal(newData, &tempDB); err != nil {
		return fmt.Errorf("les données fournies ne sont pas un JSON de base de données valide: %w", err)
	}

	// Écrire les nouvelles données dans le fichier
	// Utiliser MarshalIndent pour un formatage lisible
	formattedData, err := json.MarshalIndent(tempDB, "", "  ")
	if err != nil {
		return fmt.Errorf("impossible de formater les données JSON: %w", err)
	}

	if err := os.WriteFile(userDBPath, formattedData, 0644); err != nil {
		return fmt.Errorf("impossible d'écrire la base de données hors ligne: %w", err)
	}
	fmt.Printf("[*] Base de données hors ligne mise à jour avec succès: %s\n", userDBPath)
	return nil
}

// GetEmbeddedOfflineDB retourne la base de données embarquée.
func GetEmbeddedOfflineDB() []byte {
	return []byte(offlineDBJSON)
}

// AddSoftwareToOfflineDB permet d'ajouter ou de mettre à jour des entrées logicielles dans la base de données hors ligne de l'utilisateur.
func AddSoftwareToOfflineDB(software, version string, newVulns []Vulnerability) error {
	userDBPath := getUserOfflineDBPath()
	if userDBPath == "" {
		return fmt.Errorf("impossible de déterminer le chemin de la base de données utilisateur")
	}

	// Charger la base de données existante (ou la base embarquée si aucune n'existe)
	var currentDB map[string]map[string][]Vulnerability
	if data, err := os.ReadFile(userDBPath); err == nil {
		if err := json.Unmarshal(data, &currentDB); err != nil {
			return fmt.Errorf("impossible de lire la base de données existante: %w", err)
		}
	} else {
		// Si le fichier n'existe pas ou ne peut pas être lu, utiliser la base embarquée comme point de départ.
		if err := json.Unmarshal([]byte(offlineDBJSON), &currentDB); err != nil {
			return fmt.Errorf("impossible de parser la base de données embarquée: %w", err)
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
		return fmt.Errorf("impossible de formater les données JSON: %w", err)
	}

	dir := filepath.Dir(userDBPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("impossible de créer le répertoire de configuration: %w", err)
	}

	if err := os.WriteFile(userDBPath, formattedData, 0644); err != nil {
		return fmt.Errorf("impossible d'écrire la base de données hors ligne: %w", err)
	}
	fmt.Printf("[*] Entrée '%s %s' ajoutée/mise à jour dans la base de données hors ligne: %s\n", software, version, userDBPath)
	return nil
}
