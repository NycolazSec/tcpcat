// internal/service/engine.go
package service

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type ServiceInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// DetectService tente d'identifier le service et la version sur un port ouvert.
func DetectService(ip string, port int, timeout time.Duration) ServiceInfo {
	info := ServiceInfo{
		Name: "unknown",
	}

	target := fmt.Sprintf("%s:%d", ip, port)

	// 1. Test Handshake TLS / HTTPS (Ports web sécurisés ou SSL)
	if port == 443 || port == 8443 || port == 465 || port == 993 || port == 995 {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		dialer := &net.Dialer{Timeout: timeout}
		tlsConn, err := tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
		if err == nil {
			defer tlsConn.Close()
			info.Name = "ssl/tls"
			if port == 443 || port == 8443 {
				info.Name = "https"
				// Tentative d'extraction du serveur HTTP via TLS
				req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: tcpcat-engine/5.0\r\n\r\n", ip)
				_ = tlsConn.SetDeadline(time.Now().Add(timeout))
				_, _ = tlsConn.Write([]byte(req))
				buf := make([]byte, 512)
				n, errRead := tlsConn.Read(buf)
				if errRead == nil && n > 0 {
					info.Banner = extractServerHeader(string(buf[:n]))
				}
			}
			return info
		}
	}

	// 2. Connexion TCP classique pour lecture de bannière initiale (SSH, FTP, SMTP...)
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

		// Analyse des bannières passives immédiates
		if strings.HasPrefix(rawBanner, "SSH-") {
			info.Name = "ssh"
			info.Version = parseSSHVersion(rawBanner)
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

	// 3. Sonde HTTP brute si le port n'a pas répondu passivement
	if port == 80 || port == 8080 || port == 8000 || port == 8888 || info.Name == "unknown" {
		req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: tcpcat-engine/5.0\r\n\r\n", ip)
		_, errWrite := conn.Write([]byte(req))
		if errWrite == nil {
			_ = conn.SetDeadline(time.Now().Add(timeout))
			nHTTP, errHTTP := conn.Read(buf)
			if errHTTP == nil && nHTTP > 0 {
				resp := string(buf[:nHTTP])
				if strings.HasPrefix(resp, "HTTP/") {
					info.Name = "http"
					info.Banner = extractServerHeader(resp)
					return info
				}
			}
		}
	}

	// Déduction par numéro de port par défaut en fallback
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

func extractServerHeader(httpResp string) string {
	lines := strings.Split(httpResp, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line[7:])
		}
	}
	if len(lines) > 0 {
		return lines[0]
	}
	return ""
}

func parseSSHVersion(banner string) string {
	parts := strings.Split(banner, " ")
	if len(parts) > 0 {
		return parts[0]
	}
	return banner
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