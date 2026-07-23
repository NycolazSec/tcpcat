// internal/ports/parser.go
package ports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsePorts prend en entrée une chaîne de ports (ex: "80,443", "1-1000") ou un nombre topPorts.
func ParsePorts(portStr string, topN int) ([]int, error) {
	// 1. Si --top-ports est spécifié
	if topN > 0 {
		return GetTopPorts(topN), nil
	}

	// 2. Si aucun port n'est spécifié, on prend par défaut les top 100 ports
	if strings.TrimSpace(portStr) == "" {
		return GetTopPorts(100), nil
	}

	portMap := make(map[int]bool)
	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Nettoyage des préfixes éventuels (ex: T:80, U:53)
		if strings.HasPrefix(part, "T:") || strings.HasPrefix(part, "U:") || strings.HasPrefix(part, "S:") {
			part = part[2:]
		}

		// Plage de ports (ex: 1-1024)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("format de plage de ports invalide : %s", part)
			}
			start, err1 := strconv.Atoi(bounds[0])
			end, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("limites de plage de ports invalides : %s", part)
			}
			for i := start; i <= end; i++ {
				portMap[i] = true
			}
		} else {
			// Port individuel
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("numéro de port invalide : %s", part)
			}
			portMap[p] = true
		}
	}

	var parsedPorts []int
	for p := range portMap {
		parsedPorts = append(parsedPorts, p)
	}
	sort.Ints(parsedPorts)

	if len(parsedPorts) == 0 {
		return nil, fmt.Errorf("aucun port valide extrait")
	}

	return parsedPorts, nil
}