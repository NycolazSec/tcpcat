package service

import (
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
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

	target := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return info
	}
	defer conn.Close()

	// 1. Try a passive read with a short timeout to catch talkative services (e.g., SSH, FTP)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
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
	}

	// 2. If the port was silent, probe actively if it's a common web port.
	isWebPort := port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8000 || port == 8888
	if isWebPort {
		isTLS := port == 443 || port == 8443
		var probeConn net.Conn = conn

		// A. If it's a TLS port, wrap the connection and perform a handshake.
		if isTLS {
			tlsConfig := &tls.Config{InsecureSkipVerify: insecureSkipVerify}
			tlsClient := tls.Client(conn, tlsConfig)

			// Set a strict deadline for the handshake itself.
			if err := tlsClient.SetDeadline(time.Now().Add(timeout)); err != nil {
				info.Name = resolveDefaultPortName(port)
				return info
			}

			if err := tlsClient.Handshake(); err == nil {
				probeConn = tlsClient
			}
		}

		// B. Send the HTTP probe over the appropriate connection (raw or TLS).
		// We only do this if the connection is still valid for probing (e.g., TLS handshake succeeded).
		if (isTLS && probeConn != conn) || !isTLS {
			probeConn.SetDeadline(time.Now().Add(timeout)) // Reset deadline for the probe
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
							info.Name = "http" // It's HTTP, but no server header.
						}
						return info // We got a definitive answer.
					}
				}
			}
		}
	}

	// 3. Final fallback: If service is still unknown, use the default for the port.
	if info.Name == "unknown" {
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

	// Fallback: If no "Server" header, look for common signatures in the body.
	bodyLower := strings.ToLower(httpResp)
	if i := strings.Index(bodyLower, "<address>apache/"); i != -1 {
		signature := httpResp[i+len("<address>"):]
		if j := strings.Index(signature, " "); j != -1 {
			banner = signature[:j]
			parts := strings.Split(banner, "/")
			if len(parts) > 1 {
				software = "apache"
				version = parts[1]
				os = extractOSFromBanner(banner)
				return
			}
		}
	}
	if i := strings.Index(bodyLower, "<center>nginx/"); i != -1 {
		// Similar logic can be added for nginx and others.
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
	default:
		return "unknown"
	}
}
