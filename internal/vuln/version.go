package vuln

import (
	"strconv"
	"strings"
	"unicode"
)

func tokenizer(version string) []string {
	var parts []string
	s := version
	for s != "" {

		i := strings.IndexFunc(s, func(r rune) bool {
			return unicode.IsDigit(r) || unicode.IsLetter(r)
		})
		if i == -1 {
			break
		}
		s = s[i:]

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

func CompareVersions(v1, v2 string) int {
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

		if err1 == nil && err2 == nil {
			if num1 < num2 {
				return -1
			}
			if num1 > num2 {
				return 1
			}
			continue
		}

		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}
	return 0
}

func IsVersionAffected(targetVersion string, affected []osvAffected) bool {
	if len(affected) == 0 {
		return true
	}

	for _, a := range affected {
		for _, r := range a.Ranges {
			if r.Type == "SEMVER" {
				// Events are ordered per the OSV schema (introduced, then an
				// optional later fixed, possibly repeating). A version is
				// affected once it reaches an "introduced" boundary, and
				// stops being affected once it reaches (not merely
				// approaches) the "fixed" boundary that follows it.
				isIntroduced := false
				for _, event := range r.Events {
					if event.Introduced != "" && CompareVersions(targetVersion, event.Introduced) >= 0 {
						isIntroduced = true
					}
					if event.Fixed != "" && CompareVersions(targetVersion, event.Fixed) >= 0 {
						isIntroduced = false
					}
				}
				if isIntroduced {
					return true
				}
			}
		}
	}
	return false
}
