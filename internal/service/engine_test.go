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
			result := DetectService(tt.ip, tt.port, 2*time.Second, false, "", false)

			if result.Name == "" {
				t.Logf("Service detection returned empty name for %s:%d", tt.ip, tt.port)
			}
		})
	}
}

func TestDetectServiceTimeout(t *testing.T) {

	result := DetectService("192.0.2.1", 12345, 1*time.Millisecond, false, "", false)

	if result.Name == "" {
		t.Log("Timeout returned empty service name (expected)")
	}
}

func TestDetectServiceResponseStructure(t *testing.T) {
	result := DetectService("127.0.0.1", 22, 2*time.Second, false, "", false)

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
			result := DetectService("127.0.0.1", port, 2*time.Second, false, "", false)

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
			result := DetectService("127.0.0.1", port, 1*time.Second, false, "", false)
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
			result := DetectService("127.0.0.1", 443, 1*time.Second, tt.insecure, "", false)
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
		{"strips control bytes and high-bit garbage", "8.0.34\x00\x01\x02\xff\xfe", "8.0.34"},
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

	result := DetectService("127.0.0.1", port, 2*time.Second, false, "", false)

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
	// The banner names the exact daemon and version, so the signature table
	// should report the product ("proftpd" 1.3.5) that CVE correlation can
	// key on, not the generic "ftp".
	port := startBannerServer(t, "220 ProFTPD 1.3.5 Server ready.\r\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false, "", false)

	if result.Name != "proftpd" {
		t.Errorf("Name = %q, want proftpd", result.Name)
	}
	if result.Version != "1.3.5" {
		t.Errorf("Version = %q, want 1.3.5", result.Version)
	}
}

func TestDetectServiceFTPBannerGenericFallback(t *testing.T) {
	// A banner with no recognisable product still falls back to the generic
	// protocol name rather than "unknown".
	port := startBannerServer(t, "220 FTP server ready.\r\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false, "", false)

	if result.Name != "ftp" {
		t.Errorf("Name = %q, want ftp (generic fallback)", result.Name)
	}
}

func TestDetectServiceSMTPBanner(t *testing.T) {
	port := startBannerServer(t, "220 mail.example.com ESMTP Postfix\r\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false, "", false)

	if result.Name != "postfix" {
		t.Errorf("Name = %q, want postfix", result.Name)
	}
}

func TestDetectServiceHTTPServerHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Skipf("could not bind 127.0.0.1:8080 (already in use?): %v", err)
	}
	defer func() { _ = ln.Close() }()

	// DetectService opens multiple connections against a web port (HTTP
	// posture probe, then the banner-grab), so this fixture must serve in a
	// loop like a real server rather than handling exactly one connection.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf) // drain the GET request
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Length: 0\r\n\r\n"))
			}()
		}
	}()

	result := DetectService("127.0.0.1", 8080, 2*time.Second, false, "", false)

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

	// Same reasoning as TestDetectServiceHTTPServerHeader: 8443 is both a TLS
	// port and a web port, so DetectService opens more than one connection
	// here (TLS probe, HTTP posture probe, then the plaintext fallback).
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
			}()
		}
	}()

	result := DetectService("127.0.0.1", 8443, 2*time.Second, true, "", false)

	if result.Name != "unknown" {
		t.Errorf("Name = %q, want unknown (8443 has no resolveDefaultPortName case)", result.Name)
	}
}

func TestDetectServiceVNCBanner(t *testing.T) {
	port := startBannerServer(t, "RFB 003.008\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false, "", false)

	if result.Name != "vnc" {
		t.Errorf("Name = %q, want vnc", result.Name)
	}
	if result.Version != "003.008" {
		t.Errorf("Version = %q, want 003.008", result.Version)
	}
}

func TestDetectServicePOP3Banner(t *testing.T) {
	port := startBannerServer(t, "+OK POP3 ready\r\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false, "", false)

	if result.Name != "pop3" {
		t.Errorf("Name = %q, want pop3", result.Name)
	}
}

func TestDetectServiceIMAPBanner(t *testing.T) {
	// "Dovecot" in the banner names the product; the generic "imap" is only
	// the fallback for an unrecognised IMAP greeting.
	port := startBannerServer(t, "* OK IMAP4rev1 Dovecot ready\r\n")

	result := DetectService("127.0.0.1", port, 2*time.Second, false, "", false)

	if result.Name != "dovecot" {
		t.Errorf("Name = %q, want dovecot", result.Name)
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

// TestDetectServiceMariaDBBinaryBanner guards the case matchBannerSignature
// (not parseMySQLHandshake) actually handles: a real MariaDB handshake's
// "-MariaDB" signature match, surrounded by protocol/salt bytes that
// happen to be printable ASCII by pure chance -- stripNonPrintable alone
// can't clean this (the junk isn't non-printable), only reporting the
// matched substring as the banner does.
func TestDetectServiceMariaDBBinaryBanner(t *testing.T) {
	payload := []byte{0x4a, 0x00, 0x00, 0x00, 0x0a}
	payload = append(payload, []byte("5.5.5-10.6.12-MariaDB-1:10.6.12+maria~ubu2004-log")...)
	payload = append(payload, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x21, 0x7a, 0x3d, 0x5c, 0x2b, 0x60, 0x21, 0x00)

	port := startBannerServer(t, string(payload))

	result := DetectService("127.0.0.1", port, 2*time.Second, false, "", false)

	if result.Name != "mariadb" {
		t.Errorf("Name = %q, want mariadb", result.Name)
	}
	if result.Version != "10.6.12" {
		t.Errorf("Version = %q, want 10.6.12", result.Version)
	}
	// The distro-packaging suffix ("-1:10.6.12+maria~ubu2004-log") is kept
	// in the matched substring on purpose -- internal/vuln's distro-aware
	// CVE lookup parses it back out of Banner (see DetectDistroPackage).
	wantBanner := "10.6.12-MariaDB-1:10.6.12+maria~ubu2004-log"
	if result.Banner != wantBanner {
		t.Errorf("Banner = %q, want %q (the matched substring including the distro suffix, not the raw handshake packet)", result.Banner, wantBanner)
	}
}

func TestDetectServiceMySQLHandshake(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x00, 0x00, 0x0a}
	payload = append(payload, []byte("8.0.34")...)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00, 0x01)

	port := startBannerServer(t, string(payload))

	result := DetectService("127.0.0.1", port, 2*time.Second, false, "", false)

	if result.Name != "mysql" {
		t.Errorf("Name = %q, want mysql", result.Name)
	}
	if result.Version != "8.0.34" {
		t.Errorf("Version = %q, want 8.0.34", result.Version)
	}
	// Regression guard: the banner used to be the raw handshake packet
	// (length header, sequence byte, 0x0a protocol-version byte, and
	// trailing connection-ID bytes all included verbatim), which printed
	// as illegible binary junk instead of the version MySQL/MariaDB
	// clients actually display.
	if result.Banner != "8.0.34" {
		t.Errorf("Banner = %q, want the clean parsed version 8.0.34, not the raw handshake packet", result.Banner)
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

	// Loop-accepts (rather than a single Accept()) so a prober that opens
	// more than one connection to the same address -- e.g. probeSMB's
	// smbv1Enabled follow-up check -- gets served instead of hanging
	// against a listener nothing is draining, all the way out to its own
	// timeout.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write(response)
			}(conn)
		}
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
	// Regression guard: the dialect used to be reported as Version, which
	// fed a nonsensical CVE lookup (GetForSoftware("microsoft-ds", "SMB
	// 3.1.1")) -- it's a protocol version, not a software one. Left empty
	// now; the dialect is still visible via Banner and the finding.
	if got.Version != "" {
		t.Errorf("Version = %q, want empty (dialect is not a software version)", got.Version)
	}
	if got.Banner != "SMB 3.1.1" {
		t.Errorf("Banner = %q, want SMB 3.1.1", got.Banner)
	}
	if !containsSubstring(got.Findings, "SMB dialect negotiated: SMB 3.1.1") {
		t.Errorf("Findings = %v, want a dialect finding", got.Findings)
	}
}

func TestProbeSMBSigningNotRequired(t *testing.T) {
	resp := make([]byte, 4+64+6)
	resp[4], resp[5], resp[6], resp[7] = 0xfe, 'S', 'M', 'B'
	resp[4+64+2] = 0x00 // SecurityMode: neither bit set
	resp[4+64+4] = 0x02 // DialectRevision 0x0202 (SMB 2.0.2), little-endian
	resp[4+64+5] = 0x02

	got, ok := probeSMB(dialToStub(t, resp), 2*time.Second)
	if !ok {
		t.Fatal("probeSMB() ok = false, want true")
	}
	if !containsSubstring(got.Findings, "SMB signing is not enabled") {
		t.Errorf("Findings = %v, want a signing-not-enabled finding", got.Findings)
	}
}

func TestProbeSMBSigningRequired(t *testing.T) {
	resp := make([]byte, 4+64+6)
	resp[4], resp[5], resp[6], resp[7] = 0xfe, 'S', 'M', 'B'
	resp[4+64+2] = 0x03 // SecurityMode: both ENABLED and REQUIRED bits set
	resp[4+64+4] = 0x02 // DialectRevision 0x0202 (SMB 2.0.2), little-endian
	resp[4+64+5] = 0x02

	got, ok := probeSMB(dialToStub(t, resp), 2*time.Second)
	if !ok {
		t.Fatal("probeSMB() ok = false, want true")
	}
	if !containsSubstring(got.Findings, "SMB signing is required") {
		t.Errorf("Findings = %v, want a signing-required finding", got.Findings)
	}
}

func containsSubstring(haystack []string, substr string) bool {
	for _, s := range haystack {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func TestSMBv1EnabledAcceptsLegacyDialect(t *testing.T) {
	// A real SMB1 NEGOTIATE success response: header + WordCount=17 (the
	// standard core-protocol response size) with the rest zeroed -- only
	// Protocol/Command/Status/WordCount actually matter to smbv1Enabled.
	resp := make([]byte, 4+32+1)
	resp[4], resp[5], resp[6], resp[7] = 0xff, 'S', 'M', 'B'
	resp[8] = 0x72  // Command = NEGOTIATE
	resp[4+32] = 17 // WordCount

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
		_, _ = conn.Write(resp)
	}()

	if !smbv1Enabled(ln.Addr().String(), 2*time.Second) {
		t.Error("smbv1Enabled() = false, want true for a successful SMB1 NEGOTIATE response")
	}
}

func TestSMBv1EnabledRejectsSMB2Upgrade(t *testing.T) {
	// A server with SMBv1 disabled either upgrades to SMB2 format (0xfe)
	// or returns a non-zero status -- either way, not usable SMBv1.
	resp := make([]byte, 4+64+6)
	resp[4], resp[5], resp[6], resp[7] = 0xfe, 'S', 'M', 'B'

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
		_, _ = conn.Write(resp)
	}()

	if smbv1Enabled(ln.Addr().String(), 2*time.Second) {
		t.Error("smbv1Enabled() = true for an SMB2-format response, want false")
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
		_ = DetectService("127.0.0.1", 22, 1*time.Second, false, "", false)
	}
}

func BenchmarkDetectServiceParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		port := 22
		for pb.Next() {
			_ = DetectService("127.0.0.1", port, 1*time.Second, false, "", false)
			port++
			if port > 443 {
				port = 22
			}
		}
	})
}
