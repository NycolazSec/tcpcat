package service

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ServiceInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
	OS      string `json:"os,omitempty"`
}

var osRegexps = map[string]*regexp.Regexp{
	"ubuntu":  regexp.MustCompile(`(?i)ubuntu|ubuntudeb`),
	"debian":  regexp.MustCompile(`(?i)debian|deb`),
	"alpine":  regexp.MustCompile(`(?i)alpine`),
	"centos":  regexp.MustCompile(`(?i)centos`),
	"amazon":  regexp.MustCompile(`(?i)amazon linux|amzn`),
	"windows": regexp.MustCompile(`(?i)windows|winnt`),
	"freebsd": regexp.MustCompile(`(?i)freebsd`),
}

func DetectService(ip string, port int, timeout time.Duration, insecureSkipVerify bool) ServiceInfo {
	info := ServiceInfo{
		Name: "unknown",
	}

	target := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return info
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)

	if n > 0 {
		rawBanner := strings.TrimSpace(string(buf[:n]))
		info.Banner = sanitizeBanner(rawBanner)

		if strings.HasPrefix(rawBanner, "SSH-") {
			info.Name = "ssh"
			if strings.Contains(rawBanner, "OpenSSH") {
				info.OS = extractOSFromBanner(rawBanner)
				info.Name = "openssh"
				info.Version = parseSSHVersion(rawBanner)
			}
			return info
		}
		if strings.HasPrefix(rawBanner, "220") {
			if strings.Contains(strings.ToLower(rawBanner), "ftp") {
				info.Name = "ftp"
			} else {
				info.Name = "smtp"
			}
			return info
		}
		if strings.HasPrefix(rawBanner, "+OK") {
			info.Name = "pop3"
			return info
		}
		if strings.HasPrefix(rawBanner, "* OK") || strings.HasPrefix(rawBanner, "* PREAUTH") {
			info.Name = "imap"
			return info
		}
		if strings.HasPrefix(rawBanner, "RFB ") {
			info.Name = "vnc"
			info.Version = strings.TrimSpace(strings.TrimPrefix(rawBanner, "RFB "))
			return info
		}
		if version, ok := parseMySQLHandshake(buf[:n]); ok {
			info.Name = "mysql"
			info.Version = version
			return info
		}
	}

	isWebPort := port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8000 || port == 8888
	if isWebPort {
		isTLS := port == 443 || port == 8443
		var probeConn = conn

		if isTLS {
			tlsConfig := &tls.Config{InsecureSkipVerify: insecureSkipVerify} // #nosec G402 -- opt-in via caller flag; banner grabbing must complete the handshake against untrusted/self-signed target certs
			tlsClient := tls.Client(conn, tlsConfig)

			if err := tlsClient.SetDeadline(time.Now().Add(timeout)); err != nil {
				info.Name = resolveDefaultPortName(port)
				return info
			}

			if err := tlsClient.Handshake(); err == nil {
				probeConn = tlsClient
			}
		}

		if (isTLS && probeConn != conn) || !isTLS {
			_ = probeConn.SetDeadline(time.Now().Add(timeout))
			probe := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n", ip)
			_, errWrite := probeConn.Write([]byte(probe))
			if errWrite == nil {
				n, errRead := probeConn.Read(buf)
				if errRead == nil && n > 0 {
					resp := string(buf[:n])
					if strings.HasPrefix(resp, "HTTP/") {
						banner, software, version, os := extractServerHeader(resp)
						info.Banner = banner
						info.OS = os
						if software != "" {
							info.Name = software
							info.Version = version
						} else {
							info.Name = "http"
						}
						return info
					}
				}
			}
		}
	}

	if info.Name == "unknown" {
		if probed, ok := activeProbe(port, conn, timeout); ok {
			return probed
		}
		info.Name = resolveDefaultPortName(port)
	}

	return info
}

func sanitizeBanner(b string) string {
	cleaned := strings.ReplaceAll(b, "\r", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", " ")
	if len(cleaned) > 60 {
		return cleaned[:60] + "..."
	}
	return cleaned
}

func extractServerHeader(httpResp string) (banner string, software string, version string, os string) {
	lines := strings.Split(httpResp, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			banner = strings.TrimSpace(line[7:])
			parts := strings.Fields(banner)
			if len(parts) > 0 {
				versionParts := strings.Split(parts[0], "/")
				if len(versionParts) > 1 {
					software = strings.ToLower(versionParts[0])
					version = versionParts[1]
				}
			}
			os = extractOSFromBanner(banner)
			return
		}
	}

	bodyLower := strings.ToLower(httpResp)
	if i := strings.Index(bodyLower, "<address>apache/"); i != -1 {
		signature := httpResp[i+len("<address>"):]
		if j := strings.Index(signature, " "); j != -1 {
			banner = signature[:j]
			parts := strings.Split(banner, "/")
			if len(parts) > 1 {
				software = "apache"
				version = strings.TrimSpace(parts[1])
				os = extractOSFromBanner(banner)
				return
			}
		}
	}
	if i := strings.Index(bodyLower, "<center>nginx/"); i != -1 {
		signature := httpResp[i+len("<center>"):]
		if j := strings.Index(signature, "<"); j != -1 {
			banner = signature[:j]
			parts := strings.Split(banner, "/")
			if len(parts) > 1 {
				software = "nginx"
				version = strings.TrimSpace(parts[1])
				os = extractOSFromBanner(banner)
				return
			}
		}
	}

	return "", "", "", "unknown"
}

func extractOSFromBanner(banner string) string {
	lowerBanner := strings.ToLower(banner)
	for osName, re := range osRegexps {
		if re.MatchString(lowerBanner) {
			return osName
		}
	}
	return "unknown"
}

func parseSSHVersion(banner string) string {
	if i := strings.Index(banner, "OpenSSH_"); i != -1 {
		versionPart := banner[i+len("OpenSSH_"):]
		if j := strings.Index(versionPart, " "); j != -1 {
			return versionPart[:j]
		}
		return versionPart
	}
	return ""
}

func resolveDefaultPortName(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "domain"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 3306:
		return "mysql"
	case 3389:
		return "ms-wbt-server"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 8080:
		return "http-proxy"
	case 5900:
		return "vnc"
	case 11211:
		return "memcached"
	case 27017:
		return "mongodb"
	default:
		return "unknown"
	}
}

// parseMySQLHandshake extracts the server version string from a MySQL
// protocol-10 initial handshake packet: 3-byte payload length + 1-byte
// sequence number, then a 1-byte protocol version (0x0a) followed by a
// NUL-terminated ASCII version string. Unlike every other service handled
// here, MySQL sends this unsolicited on connect, so no probe write is
// needed -- it rides the same passive read as the SSH/FTP/SMTP banners.
func parseMySQLHandshake(b []byte) (version string, ok bool) {
	if len(b) < 6 || b[3] != 0x00 || b[4] != 0x0a {
		return "", false
	}
	rest := b[5:]
	end := bytes.IndexByte(rest, 0x00)
	if end <= 0 {
		return "", false
	}
	return string(rest[:end]), true
}

// activeProbe sends a protocol-specific probe to services that stay silent
// until spoken to (unlike SSH/FTP/SMTP/MySQL/VNC, which all greet first).
// Each prober fails closed: a wrong or rejected probe just returns false,
// which falls back to resolveDefaultPortName -- never worse than before.
func activeProbe(port int, conn net.Conn, timeout time.Duration) (ServiceInfo, bool) {
	switch port {
	case 6379:
		return probeRedis(conn, timeout)
	case 11211:
		return probeMemcached(conn, timeout)
	case 5432:
		return probePostgres(conn, timeout)
	case 445:
		return probeSMB(conn, timeout)
	case 3389:
		return probeRDP(conn, timeout)
	default:
		return ServiceInfo{}, false
	}
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i != -1 {
		return s[:i]
	}
	return s
}

// probeRedis sends INFO over RESP's inline-command form and looks for a
// bulk-string or error reply (either confirms a RESP-speaking server, even
// one that answers -NOAUTH), pulling redis_version out of the INFO body
// when auth isn't required.
func probeRedis(conn net.Conn, timeout time.Duration) (ServiceInfo, bool) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ServiceInfo{}, false
	}
	if _, err := conn.Write([]byte("INFO\r\n")); err != nil {
		return ServiceInfo{}, false
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ServiceInfo{}, false
	}
	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "$") && !strings.HasPrefix(resp, "-") {
		return ServiceInfo{}, false
	}
	info := ServiceInfo{Name: "redis", Banner: sanitizeBanner(strings.TrimSpace(firstLine(resp)))}
	if idx := strings.Index(resp, "redis_version:"); idx != -1 {
		rest := resp[idx+len("redis_version:"):]
		if end := strings.IndexAny(rest, "\r\n"); end != -1 {
			info.Version = rest[:end]
		}
	}
	return info, true
}

// probeMemcached sends the plaintext "version" command every memcached
// build has supported since 1.0.
func probeMemcached(conn net.Conn, timeout time.Duration) (ServiceInfo, bool) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ServiceInfo{}, false
	}
	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return ServiceInfo{}, false
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ServiceInfo{}, false
	}
	resp := strings.TrimSpace(string(buf[:n]))
	if !strings.HasPrefix(resp, "VERSION ") {
		return ServiceInfo{}, false
	}
	return ServiceInfo{Name: "memcached", Version: strings.TrimPrefix(resp, "VERSION "), Banner: sanitizeBanner(resp)}, true
}

// probePostgres sends an SSLRequest (the smallest valid Postgres frontend
// message: length=8, request code 80877103) and reads the single-byte
// 'S'/'N' reply every Postgres version sends before authentication, so it
// works without credentials. It only confirms the protocol and whether TLS
// is offered -- the server version itself is only revealed post-auth.
func probePostgres(conn net.Conn, timeout time.Duration) (ServiceInfo, bool) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ServiceInfo{}, false
	}
	req := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := conn.Write(req); err != nil {
		return ServiceInfo{}, false
	}
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ServiceInfo{}, false
	}
	switch buf[0] {
	case 'S':
		return ServiceInfo{Name: "postgresql", Banner: "PostgreSQL, SSL supported"}, true
	case 'N':
		return ServiceInfo{Name: "postgresql", Banner: "PostgreSQL, SSL not offered"}, true
	default:
		return ServiceInfo{}, false
	}
}

var smb2DialectNames = map[uint16]string{
	0x0202: "SMB 2.0.2",
	0x0210: "SMB 2.1",
	0x0300: "SMB 3.0",
	0x0302: "SMB 3.0.2",
	0x0311: "SMB 3.1.1",
}

// buildSMB2NegotiateRequest builds a minimal pre-3.1.1-style SMB2 NEGOTIATE
// request (no negotiate contexts needed, since the offered dialect list
// stops at 2.1) wrapped in the 4-byte NetBIOS Session Service header SMB
// direct-TCP (port 445) still expects.
func buildSMB2NegotiateRequest() []byte {
	body := make([]byte, 0, 40)
	body = append(body, 36, 0)               // StructureSize = 36
	body = append(body, 2, 0)                // DialectCount = 2
	body = append(body, 0, 0)                // SecurityMode
	body = append(body, 0, 0)                // Reserved
	body = append(body, 0, 0, 0, 0)          // Capabilities
	body = append(body, make([]byte, 16)...) // ClientGuid
	body = append(body, make([]byte, 8)...)  // ClientStartTime / Reserved2
	body = append(body, 0x02, 0x02)          // dialect 0x0202 (SMB 2.0.2)
	body = append(body, 0x10, 0x02)          // dialect 0x0210 (SMB 2.1)

	header := make([]byte, 0, 64)
	header = append(header, 0xfe, 'S', 'M', 'B') // ProtocolId
	header = append(header, 64, 0)               // StructureSize
	header = append(header, 0, 0)                // CreditCharge
	header = append(header, 0, 0, 0, 0)          // Status
	header = append(header, 0, 0)                // Command = NEGOTIATE
	header = append(header, 1, 0)                // CreditRequest
	header = append(header, 0, 0, 0, 0)          // Flags
	header = append(header, 0, 0, 0, 0)          // NextCommand
	header = append(header, make([]byte, 8)...)  // MessageId
	header = append(header, 0, 0, 0, 0)          // Reserved
	header = append(header, 0, 0, 0, 0)          // TreeId
	header = append(header, make([]byte, 8)...)  // SessionId
	header = append(header, make([]byte, 16)...) // Signature

	msg := append(header, body...)
	nbLen := len(msg)
	packet := []byte{0x00, byte(nbLen >> 16), byte(nbLen >> 8), byte(nbLen)}
	return append(packet, msg...)
}

// probeSMB sends an SMB2 NEGOTIATE request and reads back the server's
// chosen DialectRevision, giving a real SMB protocol version (2.0.2
// through 3.1.1) instead of just guessing "microsoft-ds" from the port.
func probeSMB(conn net.Conn, timeout time.Duration) (ServiceInfo, bool) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ServiceInfo{}, false
	}
	if _, err := conn.Write(buildSMB2NegotiateRequest()); err != nil {
		return ServiceInfo{}, false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 4+64+6 {
		return ServiceInfo{}, false
	}
	if buf[4] != 0xfe || buf[5] != 'S' || buf[6] != 'M' || buf[7] != 'B' {
		return ServiceInfo{}, false
	}
	dialect := uint16(buf[4+64+4]) | uint16(buf[4+64+5])<<8
	name, ok := smb2DialectNames[dialect]
	if !ok {
		return ServiceInfo{}, false
	}
	return ServiceInfo{Name: "microsoft-ds", Version: name, Banner: sanitizeBanner(name)}, true
}

var rdpProtocolNames = map[uint32]string{
	0: "Standard RDP Security",
	1: "TLS",
	2: "CredSSP (NLA)",
	8: "CredSSP with Early User Auth (NLA extended)",
}

// probeRDP sends an X.224 Connection Request carrying an RDP Negotiation
// Request (advertising SSL + CredSSP/Hybrid support) and reads back the
// server's X.224 Connection Confirm. A well-formed TPKT/X.224 reply alone
// confirms RDP; when the optional RDP Negotiation Response is present too,
// its selected-protocol field says which security layer the server picked.
func probeRDP(conn net.Conn, timeout time.Duration) (ServiceInfo, bool) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ServiceInfo{}, false
	}
	req := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT: version 3, reserved, length=19
		0x0e,       // X.224 length indicator
		0xe0,       // CR (Connection Request), CDT=0
		0x00, 0x00, // dst-ref
		0x00, 0x00, // src-ref
		0x00,                   // class/options
		0x01, 0x00, 0x08, 0x00, // RDP Negotiation Request: type=1, flags=0, length=8
		0x03, 0x00, 0x00, 0x00, // requestedProtocols = PROTOCOL_SSL | PROTOCOL_HYBRID
	}
	if _, err := conn.Write(req); err != nil {
		return ServiceInfo{}, false
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return ServiceInfo{}, false
	}
	if buf[0] != 0x03 || buf[1] != 0x00 {
		return ServiceInfo{}, false
	}
	info := ServiceInfo{Name: "ms-wbt-server", Banner: "RDP (X.224 Connection Confirm)"}
	if n >= 4+7+8 {
		selected := uint32(buf[4+7+4]) | uint32(buf[4+7+5])<<8 | uint32(buf[4+7+6])<<16 | uint32(buf[4+7+7])<<24
		if name, ok := rdpProtocolNames[selected]; ok {
			info.Version = name
		}
	}
	return info, true
}
