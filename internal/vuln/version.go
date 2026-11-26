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
		// A distro ecosystem entry (Debian/Ubuntu/...) commonly lists the
		// exact affected dpkg versions directly, alongside (or instead of)
		// a range -- an exact hit here is authoritative regardless of
		// whether CompareVersions' generic tokenizer would have ordered
		// the range boundaries correctly for dpkg's epoch:upstream-revision
		// scheme (it doesn't handle "~" pre-release ordering).
		for _, v := range a.Versions {
			if v == targetVersion {
				return true
			}
		}

		for _, r := range a.Ranges {
			// SEMVER covers most OSV feeds (GHSA, npm, PyPI, ...). ECOSYSTEM
			// is what Debian/Ubuntu's own OSV export uses for dpkg version
			// strings (e.g. "1:10.11.6-0+deb12u1") instead -- same
			// introduced/fixed event structure, just a different version
			// syntax, so the same walk applies.
			if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
				// Events are ordered per the OSV schema (introduced, then an
				// optional later fixed, possibly repeating). A version is
				// affected once it reaches an "introduced" boundary, and
				// stops being affected once it reaches (not merely
				// approaches) the "fixed" boundary that follows it.
				cmp := CompareVersions
				if r.Type == "ECOSYSTEM" {
					cmp = compareDistroVersions
				}
				isIntroduced := false
				for _, event := range r.Events {
					if event.Introduced != "" && cmp(targetVersion, event.Introduced) >= 0 {
						isIntroduced = true
					}
					if event.Fixed != "" && cmp(targetVersion, event.Fixed) >= 0 {
						isIntroduced = false
					}
					// last_affected is inclusive: the version itself is still
					// affected, anything after it is not.
					if event.LastAffected != "" && cmp(targetVersion, event.LastAffected) > 0 {
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

// compareDistroVersions compares two distro package versions. A version
// rebuilt from a service banner never carries the package's epoch (the
// "1:" of OpenSSH's "1:10.0p2-7+deb13u4"), so when only the boundary has
// one, the target is read as having the same epoch: comparing "10.0p2-..."
// token by token against "1:9.3p2-1" would otherwise start with 10 vs 1.
func compareDistroVersions(target, boundary string) int {
	if i := strings.Index(boundary, ":"); i > 0 && !strings.Contains(target, ":") && isDigits(boundary[:i]) {
		target = boundary[:i+1] + target
	}
	return CompareVersions(target, boundary)
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// distroEcosystemPrefixes are the OSV ecosystems whose versions describe a
// distribution's own package build rather than the upstream project.
var distroEcosystemPrefixes = []string{
	"AlmaLinux", "Alpaquita", "Alpine", "Azure Linux", "BellSoft Hardened Containers", "Chainguard",
	"Debian", "Echo", "Mageia", "MinimOS", "openEuler", "openSUSE", "Photon OS", "Red Hat",
	"Rocky Linux", "SUSE", "Ubuntu", "Wolfi",
}

func isDistroEcosystem(ecosystem string) bool {
	for _, p := range distroEcosystemPrefixes {
		if strings.HasPrefix(ecosystem, p) {
			return true
		}
	}
	return false
}

// upstreamPart strips the packaging from a distro version: the epoch
// ("1:"), the package revision ("-7+deb13u4", "-r0", "-19.el9") and
// repack markers ("+dfsg", "~rc1"), leaving the upstream release, e.g.
// "1:9.3p2-1" -> "9.3p2", "9.3_p2-r0" -> "9.3_p2".
func upstreamPart(v string) string {
	if i := strings.Index(v, ":"); i > 0 && isDigits(v[:i]) {
		v = v[i+1:]
	}
	if i := strings.LastIndex(v, "-"); i > 0 {
		v = v[:i]
	}
	if i := strings.IndexAny(v, "+~"); i > 0 {
		v = v[:i]
	}
	return v
}

// IsUpstreamVersionAffected decides whether an upstream version (as read
// from a banner with no distro packaging suffix, e.g. OpenSSH "10.0p2")
// is affected, given an OSV entry fetched by package name alone. Such a
// lookup returns every ecosystem's view of the CVE, and most of them
// describe something else:
//
//   - a distro entry's ranges are in that distro's package versions, and
//     an entry with no fix ("introduced 0" only: the release has not
//     patched it, or never will) says nothing about which upstream
//     versions are affected. Treating it as a range matched every version
//     ever released.
//   - a language ecosystem entry (PyPI, npm, ...) is a different product
//     that shares the name, like the "redis" client libraries.
//
// So the distro entries are only used for their fixes: the highest
// upstream release any distro shipped as a fix is taken as the upstream
// fixed version (backports keep an older upstream number, so the highest
// one is the release that carried the fix itself), and versions from it
// on are not affected. Entries without an ecosystem (the CVE's own OSV
// record) are evaluated as before. When no fix is known anywhere but a
// distro still lists the CVE as open, every version is reported affected.
func IsUpstreamVersionAffected(target string, affected []osvAffected) bool {
	if len(affected) == 0 {
		return true
	}
	upstreamFixed, openSomewhere := "", false
	for _, a := range affected {
		eco := a.Package.Ecosystem
		if eco == "" {
			if IsVersionAffected(target, []osvAffected{a}) {
				return true
			}
			continue
		}
		if !isDistroEcosystem(eco) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "ECOSYSTEM" {
				continue
			}
			fixed := false
			for _, e := range r.Events {
				if e.Fixed == "" || e.Fixed == "0" {
					continue
				}
				fixed = true
				if u := upstreamPart(e.Fixed); upstreamFixed == "" || CompareVersions(u, upstreamFixed) > 0 {
					upstreamFixed = u
				}
			}
			if !fixed && !a.unimportant() {
				openSomewhere = true
			}
		}
	}
	if upstreamFixed != "" {
		return CompareVersions(target, upstreamFixed) < 0
	}
	return openSomewhere
}
