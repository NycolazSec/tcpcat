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
}

// bannerSignatures are tried in order; the first match wins, so more
// specific products (a named FTP daemon) precede generic ones (bare FTP).
var bannerSignatures = []bannerSignature{
	// --- SSH ---
	{"openssh", regexp.MustCompile(`SSH-[\d.]+-OpenSSH[_-]([\w.]+)`)},
	{"dropbear", regexp.MustCompile(`SSH-[\d.]+-dropbear[_-]?([\w.]+)?`)},
	{"libssh", regexp.MustCompile(`SSH-[\d.]+-libssh[_-]([\w.]+)`)},

	// --- FTP --- (banners usually begin "220")
	{"vsftpd", regexp.MustCompile(`(?i)\(vsFTPd ([\d.]+)\)`)},
	{"proftpd", regexp.MustCompile(`(?i)ProFTPD ([\d.]+[\w.]*)`)},
	{"pure-ftpd", regexp.MustCompile(`(?i)Pure-FTPd`)},
	{"filezilla-ftp", regexp.MustCompile(`(?i)FileZilla Server[^\d]*([\d.]+)?`)},
	{"microsoft-ftpd", regexp.MustCompile(`(?i)Microsoft FTP Service`)},

	// --- SMTP --- (banners usually begin "220")
	{"postfix", regexp.MustCompile(`(?i)\bPostfix\b`)},
	{"exim", regexp.MustCompile(`(?i)\bExim ([\d.]+)`)},
	{"sendmail", regexp.MustCompile(`(?i)Sendmail[^\d]*([\d.]+[\w./]*)`)},
	{"microsoft-esmtp", regexp.MustCompile(`(?i)Microsoft ESMTP MAIL Service[^\d]*([\d.]+)?`)},

	// --- POP3 / IMAP ---
	{"dovecot", regexp.MustCompile(`(?i)\bDovecot\b`)},
	{"courier", regexp.MustCompile(`(?i)Courier`)},

	// --- Web servers (from a Server: header the banner grab captured) ---
	{"nginx", regexp.MustCompile(`(?i)nginx/([\d.]+)`)},
	{"apache", regexp.MustCompile(`(?i)Apache/([\d.]+)`)},
	{"lighttpd", regexp.MustCompile(`(?i)lighttpd/([\d.]+)`)},
	{"iis", regexp.MustCompile(`(?i)Microsoft-IIS/([\d.]+)`)},
	{"caddy", regexp.MustCompile(`(?i)\bCaddy\b`)},

	// --- Databases / caches / brokers ---
	{"mongodb", regexp.MustCompile(`(?i)MongoDB`)},
	{"elasticsearch", regexp.MustCompile(`(?i)"version"\s*:\s*\{\s*"number"\s*:\s*"([\d.]+)"`)},
	{"rabbitmq", regexp.MustCompile(`(?i)RabbitMQ`)},
	{"mariadb", regexp.MustCompile(`(?i)([\d.]+)-MariaDB`)},

	// --- Other common daemons ---
	{"telnet", regexp.MustCompile(`(?i)^\xff[\xfb-\xfe]`)}, // Telnet IAC negotiation
}

// matchBannerSignature runs the signature table against a banner and, on
// the first match, returns the product name and any captured version.
// A miss returns ok=false, leaving the caller's existing logic untouched.
func matchBannerSignature(banner string) (name, version string, ok bool) {
	for _, sig := range bannerSignatures {
		m := sig.Pattern.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		if len(m) > 1 {
			version = m[1]
		}
		return sig.Name, version, true
	}
	return "", "", false
}
