package service

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Many services say nothing until the client speaks: a web server or a TLS
// API on a port tcpcat does not expect one on (an Apache on 8090, the
// Kubernetes API on 6443, Pterodactyl Wings on 8080 over TLS). When the
// passive read got nothing and no port-specific probe applies, DetectService
// sends one HTTP request, the way Nmap's GetRequest probe does, and follows
// the server if it says the port speaks TLS.

// probeHTTPFallback sends "GET /" on conn. tlsKnown means a TLS handshake
// already succeeded on this port, so the request is made over TLS directly.
func probeHTTPFallback(conn net.Conn, ip string, port int, hostname string, timeout time.Duration, insecure bool, tlsInfo *TLSInfo) (ServiceInfo, bool) {
	if tlsInfo != nil {
		return identifyOverTLS(ip, port, hostname, timeout, insecure, tlsInfo)
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ServiceInfo{}, false
	}
	if _, err := conn.Write([]byte(httpRequest(ip, hostname))); err != nil {
		return ServiceInfo{}, false
	}
	resp := readSome(conn, 4096)
	switch {
	case len(resp) >= 2 && resp[0] == 0x15 && resp[1] == 0x03:
		// A TLS alert in answer to plaintext: the port speaks TLS.
		return identifyOverTLS(ip, port, hostname, timeout, insecure, nil)
	case strings.HasPrefix(resp, "HTTP/") && speaksTLSInstead(resp):
		return identifyOverTLS(ip, port, hostname, timeout, insecure, nil)
	case strings.HasPrefix(resp, "HTTP/"):
		return identifyHTTPResponse(resp, "http"), true
	}
	return ServiceInfo{}, false
}

// identifyOverTLS repeats the request over TLS.
func identifyOverTLS(ip string, port int, hostname string, timeout time.Duration, insecure bool, tlsInfo *TLSInfo) (ServiceInfo, bool) {
	if tlsInfo == nil {
		tlsInfo = probeTLS(ip, port, timeout, hostname)
	}
	cfg := &tls.Config{
		InsecureSkipVerify: insecure, // #nosec G402 -- opt-in via caller flag; identification must complete the handshake against self-signed certs
		NextProtos:         []string{"http/1.1"},
		ServerName:         hostname,
	}
	dialer := &net.Dialer{Timeout: timeout}
	c, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), cfg)
	if err != nil && !insecure {
		// Identification is not certificate validation: a self-signed
		// cluster API is still a cluster API. Retry without verifying.
		cfg.InsecureSkipVerify = true // #nosec G402 -- see above; nothing sent is secret
		c, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), cfg)
	}
	if err != nil {
		if tlsInfo != nil {
			return ServiceInfo{Name: "ssl/unknown", TLS: tlsInfo}, true
		}
		return ServiceInfo{}, false
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte(httpRequest(ip, hostname))); err != nil {
		return ServiceInfo{Name: "ssl/unknown", TLS: tlsInfo}, true
	}
	resp := readSome(c, 8192)
	if !strings.HasPrefix(resp, "HTTP/") {
		return ServiceInfo{Name: "ssl/unknown", TLS: tlsInfo}, true
	}
	info := identifyHTTPResponse(resp, "https")
	info.TLS = tlsInfo
	return info, true
}

// identifyHTTPResponse names the server from an HTTP response: the
// Kubernetes API by its Status object, otherwise the Server header's
// product, otherwise the bare protocol.
func identifyHTTPResponse(resp, protocol string) ServiceInfo {
	if isKubernetesStatus(resp) {
		return ServiceInfo{Name: "kubernetes-api", Banner: sanitizeBanner(firstLine(resp))}
	}
	banner, software, version, os := extractServerHeader(resp)
	info := ServiceInfo{Name: protocol, Banner: banner, OS: os}
	if software != "" {
		info.Name, info.Version = software, version
	}
	if os == "unknown" {
		info.OS = ""
	}
	return info
}

// isKubernetesStatus recognises the API server's answer to an anonymous
// request: a JSON Status object ({"kind": "Status", "apiVersion": "v1", ...}).
func isKubernetesStatus(resp string) bool {
	body := resp
	if i := strings.Index(resp, "\r\n\r\n"); i >= 0 {
		body = resp[i+4:]
	}
	compact := strings.Join(strings.Fields(body), "")
	return strings.Contains(compact, `"kind":"Status"`) && strings.Contains(compact, `"apiVersion":"v1"`)
}

// speaksTLSInstead recognises the plaintext error servers send back when a
// TLS port receives plain HTTP (Go's net/http, nginx, Apache).
func speaksTLSInstead(resp string) bool {
	l := strings.ToLower(resp)
	return strings.Contains(l, "http request to an https server") ||
		strings.Contains(l, "plain http request was sent to https port") ||
		strings.Contains(l, "speaking plain http to an ssl-enabled server")
}

func httpRequest(ip, hostname string) string {
	host := hostname
	if host == "" {
		host = ip
		if strings.Contains(ip, ":") {
			host = "[" + ip + "]"
		}
	}
	return fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: tcpcat\r\nAccept: */*\r\nConnection: close\r\n\r\n", host)
}

// readSome reads until max bytes, EOF or the deadline set on c. Once the
// headers are in, it waits only a little longer for the start of the body, so
// a server that ignores "Connection: close" costs 300 ms, not the timeout.
func readSome(c net.Conn, max int) string {
	buf := make([]byte, max)
	n, headers := 0, false
	for n < max {
		k, err := c.Read(buf[n:])
		n += k
		if err != nil || k == 0 {
			break
		}
		if !headers && strings.Contains(string(buf[:n]), "\r\n\r\n") {
			headers = true
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		}
	}
	return string(buf[:n])
}
