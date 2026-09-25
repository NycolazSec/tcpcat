// Distro-aware CVE correlation: a service's own version banner (e.g.
// MariaDB's "11.8.6-MariaDB-0+deb13u1") often lags the *upstream* CVE fix
// while the distro has already backported it into its own package
// revision -- an upstream-only OSV lookup would flag that host as
// vulnerable to something already patched. DetectDistroPackage recognises
// the two distro-suffix conventions verified live against the OSV API
// (see debianSuffixPattern, ubuntuSuffixPattern) and OSVScanner's caller
// (cmd/tcpcat/main.go) uses GetForDistroPackage for those instead.
//
// Known limitation: the dpkg version reconstructed from a banner can be
// missing its epoch (a purely-packaging-metadata prefix like "1:" that is
// never compiled into a service's own version string) when the banner
// doesn't restate it -- this can occasionally misalign a range comparison
// against an OSV entry whose boundaries do carry an epoch. The practical
// effect is a false negative (no distro-specific match found), which
// falls back to the existing upstream-only lookup rather than a wrong
// "not vulnerable" claim -- see the "potential (upstream version match)"
// confidence tag applied in that fallback path.
package vuln

import (
	"regexp"
	"strings"
)

// debianSuffixPattern matches a Debian dpkg backport suffix, e.g.
// "0+deb12u1" -- the release number (12) is the Debian major version,
// verified live against OSV: package "mariadb", ecosystem "Debian:12"
// returns real DEBIAN-CVE-* entries for a matching version.
var debianSuffixPattern = regexp.MustCompile(`\+deb(\d+)u\d+`)

// ubuntuSuffixPattern matches the "~ubuYYMM" convention some upstream
// projects (MariaDB's own official builds, among others) use to tag an
// Ubuntu-targeted release directly with its version, e.g. "~ubu2004" ->
// Ubuntu 20.04, "~ubu2404" -> Ubuntu 24.04. Verified live against OSV:
// package "nginx", ecosystem "Ubuntu:24.04" returns real UBUNTU-CVE-*
// entries.
//
// This does NOT cover the far more common generic Ubuntu dpkg revision
// suffix (e.g. OpenSSH's "Ubuntu-3ubuntu0.10", Apache's "(Ubuntu)") --
// that convention never encodes *which* Ubuntu release it is, so there is
// no reliable release number to extract from the string alone.
var ubuntuSuffixPattern = regexp.MustCompile(`~ubu(\d{2})(\d{2})`)

// debianSourcePackageNames maps tcpcat's own service name (see
// signatures.go/resolveDefaultPortName) to the Debian/Ubuntu *source*
// package name, for the handful of cases they differ. Verified against
// sources.debian.org/api/src/<name>/ for each entry below and each
// service name tcpcat currently identifies; anything not listed here maps
// to itself unchanged (confirmed identical for mariadb, nginx, openssh,
// postgresql, proftpd, vsftpd, dovecot, mongodb, rabbitmq, ...).
var debianSourcePackageNames = map[string]string{
	"apache": "apache2",
}

// DistroPackage is what DetectDistroPackage found: enough to run an
// ecosystem-scoped OSV query (see OSVScanner.GetForDistroPackage).
type DistroPackage struct {
	Ecosystem string // e.g. "Debian:12", "Ubuntu:24.04"
	Name      string // the distro's source package name
	Version   string // the exact dpkg version string to query with
}

// DetectDistroPackage looks for a Debian or Ubuntu packaging suffix in
// banner (tcpcat's ServiceInfo.Banner -- the raw version string as
// presented by the service, not the parsed upstream version) and, if
// found, returns enough information to run a distro-ecosystem-scoped OSV
// query instead of an upstream-only one -- which matters because a distro
// routinely backports a fix into its own package revision well before (or
// entirely without ever) bumping the upstream version number a banner
// reports, so an upstream-only version comparison can flag a host as
// vulnerable to something the distro already patched.
//
// This is deliberately conservative: only the two suffix conventions
// verified live against the OSV API (see debianSuffixPattern,
// ubuntuSuffixPattern) are recognised. A banner carrying some other
// distro marker (generic Ubuntu dpkg revisions, RPM-style ".el9", ...)
// returns ok=false rather than a guessed ecosystem string OSV would just
// reject -- callers should fall back to an upstream-only lookup and mark
// the result accordingly (e.g. "potential (upstream version match)").
func DetectDistroPackage(software, upstreamVersion, banner string) (pkg DistroPackage, ok bool) {
	name := software
	if mapped, exists := debianSourcePackageNames[software]; exists {
		name = mapped
	}

	if m := debianSuffixPattern.FindStringSubmatch(banner); m != nil {
		return DistroPackage{
			Ecosystem: "Debian:" + m[1],
			Name:      name,
			Version:   dpkgVersionFromBanner(upstreamVersion, banner),
		}, true
	}

	if m := ubuntuSuffixPattern.FindStringSubmatch(banner); m != nil {
		return DistroPackage{
			Ecosystem: "Ubuntu:" + m[1] + "." + m[2],
			Name:      name,
			Version:   dpkgVersionFromBanner(upstreamVersion, banner),
		}, true
	}

	return DistroPackage{}, false
}

// dpkgVersionFromBanner extracts the dpkg version string to query OSV
// with. MariaDB's own banner format varies: some builds restate the full
// "epoch:upstream+suffix" dpkg version after "-MariaDB-" (e.g.
// "-1:10.6.12+maria~ubu2004-log" -- already a complete, epoch-qualified
// dpkg version on its own), while a plain Debian backport only appends
// the bare revision suffix (e.g. "-0+deb13u1", missing the upstream
// version and any epoch entirely). Distinguished here by checking whether
// the captured suffix already contains the upstream version string; if
// not, it's reassembled as "<upstream>-<suffix>" -- still missing the
// epoch when the banner never states one, which is a known, accepted
// limitation of reconstructing a dpkg version from a service banner
// rather than reading it off the package database directly (see the
// package doc comment).
func dpkgVersionFromBanner(upstreamVersion, banner string) string {
	const marker = "-MariaDB-"
	i := strings.Index(banner, marker)
	if i == -1 {
		return banner
	}
	suffix := banner[i+len(marker):]
	if upstreamVersion != "" && !strings.Contains(suffix, upstreamVersion) {
		return upstreamVersion + "-" + suffix
	}
	return suffix
}
