// internal/ports/parser.go
package ports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsePorts takes a port string (e.g., "80,443", "1-1000") or a topPorts number as input.
func ParsePorts(portStr string, topN int) ([]int, error) {
	// 1. If --top-ports is specified
	if topN > 0 {
		return GetTopPorts(topN), nil
	}

	// 2. If no port is specified, default to the top 100 ports
	if strings.TrimSpace(portStr) == "" {
		return GetTopPorts(100), nil
	}

	portMap := make(map[int]bool)
	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Clean up potential prefixes (e.g., T:80, U:53)
		if strings.HasPrefix(part, "T:") || strings.HasPrefix(part, "U:") || strings.HasPrefix(part, "S:") {
			part = part[2:]
		}

		// Port range (e.g., 1-1024)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", part)
			}
			start, err1 := strconv.Atoi(bounds[0])
			end, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range limits: %s", part)
			}
			for i := start; i <= end; i++ {
				portMap[i] = true
			}
		} else {
			// Individual port
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port number: %s", part)
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
		return nil, fmt.Errorf("no valid ports extracted")
	}

	return parsedPorts, nil
}