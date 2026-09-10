package service

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDetectServiceLocalhost(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port int
	}{
		{"SSH", "127.0.0.1", 22},
		{"HTTP", "127.0.0.1", 80},
		{"HTTPS", "127.0.0.1", 443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectService(tt.ip, tt.port, 2*time.Second, false)

			if result.Name == "" {
				t.Logf("Service detection returned empty name for %s:%d", tt.ip, tt.port)
			}
		})
	}
}

func TestDetectServiceTimeout(t *testing.T) {

	result := DetectService("192.0.2.1", 12345, 1*time.Millisecond, false)

	if result.Name == "" {
		t.Log("Timeout returned empty service name (expected)")
	}
}

func TestDetectServiceResponseStructure(t *testing.T) {
	result := DetectService("127.0.0.1", 22, 2*time.Second, false)

	if result.Name == "" {
		t.Error("Result has empty Name")
	}

	if len(result.Version) > 100 {
		t.Errorf("Version unreasonably long: %d chars", len(result.Version))
	}

	if len(result.Banner) > 1000 {
		t.Errorf("Banner unreasonably long: %d chars", len(result.Banner))
	}

	if len(result.OS) > 50 {
		t.Errorf("OS unreasonably long: %d chars", len(result.OS))
	}
}

func TestDetectServiceCommonPorts(t *testing.T) {
	commonPorts := []int{22, 80, 443, 3306, 5432, 6379}

	for _, port := range commonPorts {
		t.Run(string(rune(port)), func(t *testing.T) {
			result := DetectService("127.0.0.1", port, 2*time.Second, false)

			if len(result.Name) > 50 {
				t.Errorf("Service name unreasonably long: %s", result.Name)
			}
		})
	}
}

func TestDetectServiceConcurrency(t *testing.T) {
	results := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(port int) {
			result := DetectService("127.0.0.1", port, 1*time.Second, false)
			results <- result.Name != ""
		}(22 + i)
	}

	for i := 0; i < 10; i++ {
		<-results
	}
}

func TestDetectServiceInsecureSkipVerify(t *testing.T) {

	tests := []struct {
		name     string
		insecure bool
	}{
		{"secure", false},
		{"insecure", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectService("127.0.0.1", 443, 1*time.Second, tt.insecure)
			if result.Name == "" {
				t.Log("Expected behavior with insecure flag")
			}
		})
	}
}

func TestSanitizeBanner(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"short", "SSH-2.0-OpenSSH_8.9", "SSH-2.0-OpenSSH_8.9"},
		{"strips crlf", "SSH-2.0-OpenSSH_8.9\r\nExtra\n", "SSH-2.0-OpenSSH_8.9 Extra "},
		{"truncates long banners", strings.Repeat("A", 80), strings.Repeat("A", 60) + "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeBanner(tt.in); got != tt.want {
				t.Errorf("sanitizeBanner(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExtractOSFromBanner(t *testing.T) {
	tests := []struct {
		banner string
		want   string
	}{
		{"Apache/2.4.41 (Ubuntu)", "ubuntu"},
		{"Apache/2.4.38 (Debian)", "debian"},
		{"nginx/1.18.0 (Alpine)", "alpine"},
		{"Apache/2.4.6 (CentOS)", "centos"},
		{"Apache/2.4.41 (Amazon Linux)", "amazon"},
		{"Microsoft-IIS/10.0 (Windows)", "windows"},
		{"Apache/2.4.54 (FreeBSD)", "freebsd"},
		{"nginx/1.20.1", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.banner, func(t *testing.T) {
			if got := extractOSFromBanner(tt.banner); got != tt.want {
				t.Errorf("extractOSFromBanner(%q) = %q, want %q", tt.banner, got, tt.want)
			}
		})
	}
}

func TestParseSSHVersion(t *testing.T) {
	tests := []struct {
		banner string
		want   string
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4", "8.9p1"},
		{"SSH-2.0-OpenSSH_9.6", "9.6"},
		{"SSH-2.0-libssh_0.9.6", ""},
	}
	for _, tt := range tests {
		t.Run(tt.banner, func(t *testing.T) {
			if got := parseSSHVersion(tt.banner); got != tt.want {
				t.Errorf("parseSSHVersion(%q) = %q, want %q", tt.banner, got, tt.want)
			}
		})
	}
}

func TestResolveDefaultPortName(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"}, {53, "domain"},
		{80, "http"}, {110, "pop3"}, {143, "imap"}, {443, "https"}, {445, "microsoft-ds"},
		{3306, "mysql"}, {3389, "ms-wbt-server"}, {5432, "postgresql"}, {6379, "redis"},
		{8080, "http-proxy"}, {5900, "vnc"}, {11211, "memcached"}, {27017, "mongodb"},
		{9999, "unknown"},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.port), func(t *testing.T) {
			if got := resolveDefaultPortName(tt.port); got != tt.want {
				t.Errorf("resolveDefaultPortName(%d) = %q, want %q", tt.port, got, tt.want)
			}
		})
	}
}

func TestExtractServerHeader(t *testing.T) {
	tests := []struct {
		name         string
		resp         string
		wantSoftware string
		wantVersion  string
		wantOS       string
	}{
		{
			name:         "nginx server header",
			resp:         "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n",
			wantSoftware: "nginx",
			wantVersion:  "1.18.0",
			wantOS:       "ubuntu",
		},
		{
			name:         "apache server header",
			resp:         "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Debian)\r\n\r\n",
			wantSoftware: "apache",
			wantVersion:  "2.4.41",
			wantOS:       "debian",
		},
		{
			// The <address> signature is cut at the first space, so the
			// "(Ubuntu)" suffix never reaches extractOSFromBanner here.
			name:         "no server header, apache address fallback",
			resp:         "HTTP/1.1 404 Not Found\r\n\r\n<html><body><address>Apache/2.4.29 (Ubuntu) Server</address></body></html>",
			wantSoftware: "apache",
			wantVersion:  "2.4.29",
			wantOS:       "unknown",
		},
		{
			name:         "no server header, nginx center fallback",
			resp:         "HTTP/1.1 404 Not Found\r\n\r\n<html><center>nginx/1.20.1</center></html>",
			wantSoftware: "nginx",
			wantVersion:  "1.20.1",
			wantOS:       "unknown",
		},
		{
			name:         "nothing recognizable",
			resp:         "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello",
			wantSoftware: "",
			wantVersion:  "",
			wantOS:       "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, software, version, os := extractServerHeader(tt.resp)
			if software != tt.wantSoftware {
				t.Errorf("software = %q, want %q", software, tt.wantSoftware)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
			if os != tt.wantOS {
				t.Errorf("os = %q, want %q", os, tt.wantOS)
			}
		})
	}
}

// startBannerServer listens on 127.0.0.1 with an OS-assigned port, writes
// banner to the first connection it accepts, and returns the listener's
// port so the caller can point DetectService at it.
func startBannerServer(t *testing.T, banner string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte(banner))
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

func TestDetectServiceSSHBanner(t *testing.T) {
	port := startBannerServer(t, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false)

	if result.Name != "openssh" {
		t.Errorf("Name = %q, want openssh", result.Name)
	}
	if result.Version != "9.6p1" {
		t.Errorf("Version = %q, want 9.6p1", result.Version)
	}
	if result.OS != "ubuntu" {
		t.Errorf("OS = %q, want ubuntu", result.OS)
	}
}

func TestDetectServiceFTPBanner(t *testing.T) {
	port := startBannerServer(t, "220 ProFTPD 1.3.5 Server ready.\r\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false)

	if result.Name != "ftp" {
		t.Errorf("Name = %q, want ftp", result.Name)
	}
}

func TestDetectServiceSMTPBanner(t *testing.T) {
	port := startBannerServer(t, "220 mail.example.com ESMTP Postfix\r\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false)

	if result.Name != "smtp" {
		t.Errorf("Name = %q, want smtp", result.Name)
	}
}

func TestDetectServiceHTTPServerHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Skipf("could not bind 127.0.0.1:8080 (already in use?): %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf) // drain the GET request
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Length: 0\r\n\r\n"))
	}()

	result := DetectService("127.0.0.1", 8080, 2*time.Second, false)

	if result.Name != "nginx" {
		t.Errorf("Name = %q, want nginx", result.Name)
	}
	if result.Version != "1.24.0" {
		t.Errorf("Version = %q, want 1.24.0", result.Version)
	}
	if result.OS != "ubuntu" {
		t.Errorf("OS = %q, want ubuntu", result.OS)
	}
}

func TestDetectServiceTLSHandshakeFailureFallsBack(t *testing.T) {
	// 8443 is in isWebPort's TLS set; a plain (non-TLS) listener there makes
	// the handshake fail, exercising the fallback-to-plaintext-probe path.
	ln, err := net.Listen("tcp", "127.0.0.1:8443")
	if err != nil {
		t.Skipf("could not bind 127.0.0.1:8443 (already in use?): %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	}()

	result := DetectService("127.0.0.1", 8443, 2*time.Second, true)

	if result.Name != "unknown" {
		t.Errorf("Name = %q, want unknown (8443 has no resolveDefaultPortName case)", result.Name)
	}
}

func TestDetectServiceVNCBanner(t *testing.T) {
	port := startBannerServer(t, "RFB 003.008\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false)

	if result.Name != "vnc" {
		t.Errorf("Name = %q, want vnc", result.Name)
	}
	if result.Version != "003.008" {
		t.Errorf("Version = %q, want 003.008", result.Version)
	}
}

func TestDetectServicePOP3Banner(t *testing.T) {
	port := startBannerServer(t, "+OK POP3 ready\r\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false)

	if result.Name != "pop3" {
		t.Errorf("Name = %q, want pop3", result.Name)
	}
}

func TestDetectServiceIMAPBanner(t *testing.T) {
	port := startBannerServer(t, "* OK IMAP4rev1 Dovecot ready\r\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false)

	if result.Name != "imap" {
		t.Errorf("Name = %q, want imap", result.Name)
	}
}

func TestParseMySQLHandshake(t *testing.T) {
	valid := []byte{0x00, 0x00, 0x00, 0x00, 0x0a}
	valid = append(valid, []byte("8.0.34")...)
	valid = append(valid, 0x00, 'x', 'y')

	version, ok := parseMySQLHandshake(valid)
	if !ok || version != "8.0.34" {
		t.Errorf("parseMySQLHandshake(valid) = (%q, %v), want (8.0.34, true)", version, ok)
	}

	if _, ok := parseMySQLHandshake([]byte{0x01, 0x02}); ok {
		t.Error("expected false for too-short input")
	}
	if _, ok := parseMySQLHandshake([]byte{0x00, 0x00, 0x00, 0x00, 0x09, 'x', 0x00}); ok {
		t.Error("expected false for non-0x0a protocol version byte")
	}
}

func TestDetectServiceMySQLHandshake(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x00, 0x00, 0x0a}
	payload = append(payload, []byte("8.0.34")...)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00, 0x01)

	port := startBannerServer(t, string(payload))

	result := DetectService("127.0.0.1", port, 2*time.Second, false)

	if result.Name != "mysql" {
		t.Errorf("Name = %q, want mysql", result.Name)
	}
	if result.Version != "8.0.34" {
		t.Errorf("Version = %q, want 8.0.34", result.Version)
	}
}

// dialToStub starts a listener that, on its first accepted connection,
// drains whatever the client writes and then writes back response, and
// returns a client connection dialed to it -- used to unit-test the
// active-probe functions directly without needing to bind their real
// (sometimes privileged) well-known ports.
func dialToStub(t *testing.T, response []byte) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(response)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestProbeRedisParsesVersion(t *testing.T) {
	body := "redis_version:7.2.4\r\nredis_mode:standalone\r\n"
	resp := fmt.Sprintf("$%d\r\n%s\r\n", len(body), body)

	got, ok := probeRedis(dialToStub(t, []byte(resp)), 2*time.Second)
	if !ok {
		t.Fatal("probeRedis() ok = false, want true")
	}
	if got.Name != "redis" || got.Version != "7.2.4" {
		t.Errorf("probeRedis() = %+v, want Name=redis Version=7.2.4", got)
	}
}

func TestProbeRedisRejectsNonRESP(t *testing.T) {
	if _, ok := probeRedis(dialToStub(t, []byte("not a redis reply")), 2*time.Second); ok {
		t.Error("probeRedis() ok = true for non-RESP reply, want false")
	}
}

func TestProbeMemcachedParsesVersion(t *testing.T) {
	got, ok := probeMemcached(dialToStub(t, []byte("VERSION 1.6.21\r\n")), 2*time.Second)
	if !ok || got.Version != "1.6.21" {
		t.Errorf("probeMemcached() = %+v, %v, want Version=1.6.21, true", got, ok)
	}
}

func TestProbeMemcachedRejectsUnknownReply(t *testing.T) {
	if _, ok := probeMemcached(dialToStub(t, []byte("ERROR\r\n")), 2*time.Second); ok {
		t.Error("probeMemcached() ok = true for ERROR reply, want false")
	}
}

func TestProbePostgresSSLSupported(t *testing.T) {
	got, ok := probePostgres(dialToStub(t, []byte{'S'}), 2*time.Second)
	if !ok || got.Name != "postgresql" {
		t.Errorf("probePostgres() = %+v, %v, want Name=postgresql, true", got, ok)
	}
}

func TestProbePostgresSSLNotOffered(t *testing.T) {
	got, ok := probePostgres(dialToStub(t, []byte{'N'}), 2*time.Second)
	if !ok || got.Name != "postgresql" {
		t.Errorf("probePostgres() = %+v, %v, want Name=postgresql, true", got, ok)
	}
}

func TestProbePostgresRejectsUnexpectedByte(t *testing.T) {
	if _, ok := probePostgres(dialToStub(t, []byte{'E'}), 2*time.Second); ok {
		t.Error("probePostgres() ok = true for unexpected byte, want false")
	}
}

func TestProbeSMBParsesDialect(t *testing.T) {
	resp := make([]byte, 4+64+6)
	resp[4], resp[5], resp[6], resp[7] = 0xfe, 'S', 'M', 'B'
	resp[4+64+4] = 0x11 // DialectRevision 0x0311 (SMB 3.1.1), little-endian
	resp[4+64+5] = 0x03

	got, ok := probeSMB(dialToStub(t, resp), 2*time.Second)
	if !ok {
		t.Fatal("probeSMB() ok = false, want true")
	}
	if got.Version != "SMB 3.1.1" {
		t.Errorf("Version = %q, want SMB 3.1.1", got.Version)
	}
}

func TestProbeSMBRejectsShortReply(t *testing.T) {
	if _, ok := probeSMB(dialToStub(t, []byte{0x00, 0x00}), 2*time.Second); ok {
		t.Error("probeSMB() ok = true for short reply, want false")
	}
}

func TestProbeRDPConfirmsWithoutNegotiateResponse(t *testing.T) {
	resp := []byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00}

	got, ok := probeRDP(dialToStub(t, resp), 2*time.Second)
	if !ok || got.Name != "ms-wbt-server" {
		t.Errorf("probeRDP() = %+v, %v, want Name=ms-wbt-server, true", got, ok)
	}
	if got.Version != "" {
		t.Errorf("Version = %q, want empty (no negotiation response present)", got.Version)
	}
}

func TestProbeRDPParsesSelectedProtocol(t *testing.T) {
	resp := make([]byte, 4+7+8)
	resp[0], resp[1] = 0x03, 0x00
	resp[4+7+4] = 0x02 // selectedProtocol = 2 (CredSSP/NLA), little-endian

	got, ok := probeRDP(dialToStub(t, resp), 2*time.Second)
	if !ok {
		t.Fatal("probeRDP() ok = false, want true")
	}
	if got.Version != "CredSSP (NLA)" {
		t.Errorf("Version = %q, want CredSSP (NLA)", got.Version)
	}
}

func TestProbeRDPRejectsNonTPKT(t *testing.T) {
	if _, ok := probeRDP(dialToStub(t, []byte{0x00, 0x00, 0x00, 0x00}), 2*time.Second); ok {
		t.Error("probeRDP() ok = true for non-TPKT reply, want false")
	}
}

func BenchmarkDetectService(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = DetectService("127.0.0.1", 22, 1*time.Second, false)
	}
}

func BenchmarkDetectServiceParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		port := 22
		for pb.Next() {
			_ = DetectService("127.0.0.1", port, 1*time.Second, false)
			port++
			if port > 443 {
				port = 22
			}
		}
	})
}
