package target

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

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

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		for _, item := range fields {
			parsed, err := ParseTarget(item)
			if err != nil {
				continue
			}
			targets = append(targets, parsed...)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("erreur lors de la lecture du fichier : %w", err)
	}

	return targets, nil
}
