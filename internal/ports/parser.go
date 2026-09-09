package ports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func ParsePorts(portStr string, topN int) ([]int, error) {

	if topN > 0 {
		return GetTopPorts(topN), nil
	}

	if strings.TrimSpace(portStr) == "" {
		return GetTopPorts(100), nil
	}

	portMap := make(map[int]bool)
	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		if strings.HasPrefix(part, "T:") || strings.HasPrefix(part, "U:") || strings.HasPrefix(part, "S:") {
			part = part[2:]
		}

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
