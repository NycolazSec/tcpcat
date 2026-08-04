package vuln

import (
	"strconv"
	"strings"
	"unicode"
)

// tokenizer splits a version string into a slice of numbers and strings.
// It handles complex versions like "9.6p1" -> ["9", "6", "p", "1"].
func tokenizer(version string) []string {
	var parts []string
	s := version
	for s != "" {
		// Find first digit or letter
		i := strings.IndexFunc(s, func(r rune) bool {
			return unicode.IsDigit(r) || unicode.IsLetter(r)
		})
		if i == -1 {
			break // No more parts
		}
		s = s[i:] // Trim leading separators

		// Find end of current part (digit or letter sequence)
		isDigit := unicode.IsDigit(rune(s[0]))
		j := strings.IndexFunc(s, func(r rune) bool {
			return (isDigit && !unicode.IsDigit(r)) || (!isDigit && !unicode.IsLetter(r))
		})

		if j == -1 {
			parts = append(parts, s)
			s = ""
		} else {
			parts = append(parts, s[:j])
			s = s[j:]
		}
	}
	return parts
}

// CompareVersions compares two version strings (e.g., "9.6p1", "7.2").
// It does not use any external dependencies.
// Returns:
// -1 if v1 < v2
//
//	0 if v1 == v2
//	1 if v1 > v2
func CompareVersions(v1, v2 string) int {
	// Handle epoch prefixes (e.g., "1:9.6p1-3" -> "9.6p1-3")
	if i := strings.Index(v1, ":"); i != -1 {
		v1 = v1[i+1:]
	}
	if i := strings.Index(v2, ":"); i != -1 {
		v2 = v2[i+1:]
	}

	parts1 := tokenizer(v1)
	parts2 := tokenizer(v2)

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		p1 := ""
		if i < len(parts1) {
			p1 = parts1[i]
		}
		p2 := ""
		if i < len(parts2) {
			p2 = parts2[i]
		}

		num1, err1 := strconv.Atoi(p1)
		num2, err2 := strconv.Atoi(p2)

		// If both are numbers, compare numerically
		if err1 == nil && err2 == nil {
			if num1 < num2 {
				return -1
			}
			if num1 > num2 {
				return 1
			}
			continue
		}

		// If one or both are strings, compare lexicographically.
		// This handles cases like "p1" > "" correctly for patch levels.
		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}
	return 0
}

// IsVersionAffected checks if a target version falls within the affected ranges of a vulnerability.
func IsVersionAffected(targetVersion string, affected []osvAffected) bool {
	if len(affected) == 0 {
		return true // No info, assume affected to be safe
	}

	// First, check the explicit list of affected versions, which is common for OS-specific packages.
	// This is a quick path for exact or substring matches (e.g., Ubuntu versions).
	for _, a := range affected {
		for _, v := range a.Versions {
			if strings.Contains(v, targetVersion) {
				return true
			}
		}
	}

	// If no direct match, fall back to SEMVER range comparison.
	for _, a := range affected {
		for _, r := range a.Ranges {
			if r.Type == "SEMVER" {
				isAffected := false
				for _, event := range r.Events {
					// If introduced is "0" or empty, it means all versions before a fix are affected.
					introducedCondition := event.Introduced == "0" || event.Introduced == "" || CompareVersions(targetVersion, event.Introduced) >= 0

					if introducedCondition {
						isAffected = true
					}
					// If the version is greater than or equal to a fixed version, it's not affected.
					if event.Fixed != "" && CompareVersions(targetVersion, event.Fixed) >= 0 {
						isAffected = false
					}
				}
				if isAffected {
					return true // The version is within an affected range.
				}
			}
		}
	}
	return false
}
