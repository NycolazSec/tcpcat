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

	if port == 443 || port == 8443 || port == 465 || port == 993 || port == 995 {
		tlsConfig := &tls.Config{InsecureSkipVerify: insecureSkipVerify}
		dialer := &net.Dialer{Timeout: timeout}
		tlsConn, err := tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
		if err == nil {
			defer tlsConn.Close()
			info.Name = "ssl/tls"
			if port == 443 || port == 8443 {
				info.Name = "https"
				req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: tcpcat-engine/5.0\r\n\r\n", ip)
				_ = tlsConn.SetDeadline(time.Now().Add(timeout))
				_, _ = tlsConn.Write([]byte(req))
				buf := make([]byte, 512)
				n, _ := tlsConn.Read(buf)
				banner, software, version, os := extractServerHeader(string(buf[:n]))
				info.Banner = banner
				if software != "" {
					info.Name = software
					info.Version = version
				}
				info.OS = os
			}
			return info
		}
	}

	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return info
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, errRead := conn.Read(buf)

	if errRead == nil && n > 0 {
		rawBanner := strings.TrimSpace(string(buf[:n]))
		info.Banner = sanitizeBanner(rawBanner)

		if strings.HasPrefix(rawBanner, "SSH-") {
			info.Name = "ssh"
			if strings.Contains(rawBanner, "OpenSSH") {
				info.OS = extractOSFromBanner(rawBanner)
				info.Name = "openssh"
				info.Version = parseSSHVersion(rawBanner)
			} else {
				parts := strings.Split(rawBanner, " ")
				info.Version = parts[0]
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

	if port == 80 || port == 8080 || port == 8000 || port == 8888 || info.Name == "unknown" {
		req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: tcpcat-engine/5.0\r\n\r\n", ip)
		_, errWrite := conn.Write([]byte(req))
		if errWrite == nil {
			_ = conn.SetDeadline(time.Now().Add(timeout))
			nHTTP, errHTTP := conn.Read(buf)
			if errHTTP == nil && nHTTP > 0 {
				resp := string(buf[:nHTTP])
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
