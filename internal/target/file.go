// internal/target/file.go
package target

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadFromFile lit un fichier (-iL) et extrait toutes les cibles IP/DNS.
func LoadFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("impossible d'ouvrir le fichier de cibles '%s': %w", filePath, err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Ignorer les lignes vides et les commentaires
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Une ligne peut contenir plusieurs cibles séparées par des espaces
		fields := strings.Fields(line)
		for _, item := range fields {
			parsed, err := ParseTarget(item)
			if err != nil {
				continue // Ignore les entrées malformées
			}
			targets = append(targets, parsed...)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("erreur lors de la lecture du fichier : %w", err)
	}

	return targets, nil
}