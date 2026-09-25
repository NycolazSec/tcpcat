package service

import "regexp"

// The passive banner grab used to recognise a handful of protocols by a
// bare prefix ("220" -> smtp) and rarely pulled a version out of the line.
// A real service scanner earns its keep by naming the exact software and
// version, which is what feeds accurate CVE correlation downstream. This
// table is a curated set of banner signatures -- product name plus a
// version-capturing regex -- run against the banner before the port-number
// fallback. It is deliberately smaller and more conservative than nmap's
// nmap-service-probes corpus: every entry here is a real, common daemon
// whose banner shape is stable, matched with an anchored expression so a
// stray substring can't misidentify a service.

// bannerSignature identifies one product from a banner line.
type bannerSignature struct {
	// Name is the product reported when Pattern matches (e.g. "vsftpd").
	Name string

	// Pattern matches the banner. When it has a capture group, the first
	// group is taken as the version.
	Pattern *regexp.Regexp

	// Binary marks a signature whose underlying protocol isn't itself a
	// text banner -- MySQL/MariaDB's wire handshake and Telnet's IAC
	// negotiation both lead with a raw binary packet (length header,
	// sequence byte, salt/capability bytes for MySQL; IAC control bytes
	// for Telnet) that the regex happens to find a match inside. Those
	// surrounding bytes are not something a human would ever read as a
	// banner -- often illegible control characters, sometimes printable
	// ASCII by pure chance -- so the caller reports just the matched
	// substring as the banner instead of the raw response.
	Binary bool
}

// bannerSignatures are tried in order; the first match wins, so more
// specific products (a named FTP daemon) precede generic ones (bare FTP).
var bannerSignatures = []bannerSignature{
	// --- SSH ---
	{"openssh", regexp.MustCompile(`SSH-[\d.]+-OpenSSH[_-]([\w.]+)`), false},
	{"dropbear", regexp.MustCompile(`SSH-[\d.]+-dropbear[_-]?([\w.]+)?`), false},
	{"libssh", regexp.MustCompile(`SSH-[\d.]+-libssh[_-]([\w.]+)`), false},

	// --- FTP --- (banners usually begin "220")
	{"vsftpd", regexp.MustCompile(`(?i)\(vsFTPd ([\d.]+)\)`), false},
	{"proftpd", regexp.MustCompile(`(?i)ProFTPD ([\d.]+[\w.]*)`), false},
	{"pure-ftpd", regexp.MustCompile(`(?i)Pure-FTPd`), false},
	{"filezilla-ftp", regexp.MustCompile(`(?i)FileZilla Server[^\d]*([\d.]+)?`), false},
	{"microsoft-ftpd", regexp.MustCompile(`(?i)Microsoft FTP Service`), false},

	// --- SMTP --- (banners usually begin "220")
	{"postfix", regexp.MustCompile(`(?i)\bPostfix\b`), false},
	{"exim", regexp.MustCompile(`(?i)\bExim ([\d.]+)`), false},
	{"sendmail", regexp.MustCompile(`(?i)Sendmail[^\d]*([\d.]+[\w./]*)`), false},
	{"microsoft-esmtp", regexp.MustCompile(`(?i)Microsoft ESMTP MAIL Service[^\d]*([\d.]+)?`), false},

	// --- POP3 / IMAP ---
	{"dovecot", regexp.MustCompile(`(?i)\bDovecot\b`), false},
	{"courier", regexp.MustCompile(`(?i)Courier`), false},

	// --- Web servers (from a Server: header the banner grab captured) ---
	{"nginx", regexp.MustCompile(`(?i)nginx/([\d.]+)`), false},
	{"apache", regexp.MustCompile(`(?i)Apache/([\d.]+)`), false},
	{"lighttpd", regexp.MustCompile(`(?i)lighttpd/([\d.]+)`), false},
	{"iis", regexp.MustCompile(`(?i)Microsoft-IIS/([\d.]+)`), false},
	{"caddy", regexp.MustCompile(`(?i)\bCaddy\b`), false},

	// --- Databases / caches / brokers ---
	{"mongodb", regexp.MustCompile(`(?i)MongoDB`), false},
	{"elasticsearch", regexp.MustCompile(`(?i)"version"\s*:\s*\{\s*"number"\s*:\s*"([\d.]+)"`), false},
	{"rabbitmq", regexp.MustCompile(`(?i)RabbitMQ`), false},
	// The trailing [\w.:+~-]* deliberately keeps whatever distro-packaging
	// suffix follows "-MariaDB" (e.g. "-1:10.6.12+maria~ubu2004-log" or
	// "-0+deb13u1") in the matched substring: it's legitimate, printable
	// version information (not binary junk to strip), and is what
	// internal/vuln's distro-aware CVE lookup parses back out of Banner.
	{"mariadb", regexp.MustCompile(`(?i)([\d.]+)-MariaDB[\w.:+~-]*`), true},

	// --- Other common daemons ---
	{"telnet", regexp.MustCompile(`(?i)^\xff[\xfb-\xfe]`), true}, // Telnet IAC negotiation
}

// matchBannerSignature runs the signature table against a banner and, on
// the first match, returns the product name, any captured version, the
// full matched substring (matched), and whether the underlying protocol is
// binary (see bannerSignature.Binary). A miss returns ok=false, leaving the
// caller's existing logic untouched.
func matchBannerSignature(banner string) (name, version, matched string, binary bool, ok bool) {
	for _, sig := range bannerSignatures {
		m := sig.Pattern.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		if len(m) > 1 {
			version = m[1]
		}
		return sig.Name, version, m[0], sig.Binary, true
	}
	return "", "", "", false, false
}
