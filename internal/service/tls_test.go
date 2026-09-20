package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0301, "TLS 1.0"}, // raw wire value, same as the constant above
	}
	for _, tt := range tests {
		if got := tlsVersionName(tt.version); got != tt.want {
			t.Errorf("tlsVersionName(%#x) = %q, want %q", tt.version, got, tt.want)
		}
	}

	if got := tlsVersionName(0x9999); got != "0x9999" {
		t.Errorf("tlsVersionName(unknown) = %q, want hex fallback", got)
	}
}

func TestIsWeakTLSVersion(t *testing.T) {
	// 0x0300 is SSLv3's wire version; tls.VersionSSL30 itself is deprecated
	// (staticcheck SA1019) purely as a constant to reference, even though
	// isWeakTLSVersion's own "< TLS 1.2" check still needs to cover it.
	weak := []uint16{0x0300, tls.VersionTLS10, tls.VersionTLS11}
	for _, v := range weak {
		if !isWeakTLSVersion(v) {
			t.Errorf("isWeakTLSVersion(%#x) = false, want true", v)
		}
	}

	strong := []uint16{tls.VersionTLS12, tls.VersionTLS13}
	for _, v := range strong {
		if isWeakTLSVersion(v) {
			t.Errorf("isWeakTLSVersion(%#x) = true, want false", v)
		}
	}
}

func TestIsWeakCipherSuite(t *testing.T) {
	insecure := tls.InsecureCipherSuites()
	if len(insecure) == 0 {
		t.Skip("crypto/tls reports no insecure cipher suites on this Go version")
	}
	if !isWeakCipherSuite(insecure[0].ID) {
		t.Errorf("isWeakCipherSuite(%#x) = false, want true (from tls.InsecureCipherSuites)", insecure[0].ID)
	}

	secure := tls.CipherSuites() // modern, non-deprecated suites
	if len(secure) == 0 {
		t.Fatal("crypto/tls reports no secure cipher suites")
	}
	if isWeakCipherSuite(secure[0].ID) {
		t.Errorf("isWeakCipherSuite(%#x) = true, want false (from tls.CipherSuites)", secure[0].ID)
	}
}

// selfSignedCert generates a throwaway self-signed certificate for
// commonName, valid from now until notAfter, so tests can exercise
// probeTLS's expiry/self-signed/hostname-mismatch logic without any
// external dependency (no openssl, no fixture files).
func selfSignedCert(t *testing.T, commonName string, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// A CommonName alone doesn't satisfy hostname verification under modern
	// Go: CN fallback matching was dropped, so whatever is being verified
	// against has to appear in a SAN -- IPAddresses for an address, DNSNames
	// for a name. Without this a fixture cert fails verification against its
	// own subject, which is not how any real certificate behaves.
	if ip := net.ParseIP(commonName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{commonName}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSTestServer listens on 127.0.0.1 with the given certificate and
// minimum TLS version, accepting and handshaking exactly one connection
// (probeTLS's own full lifecycle -- dial, handshake, read cert, close --
// so one accept is all a single probeTLS call needs).
func startTLSTestServer(t *testing.T, cert tls.Certificate, minVersion uint16) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
		MaxVersion:   minVersion,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if tlsConn, ok := conn.(*tls.Conn); ok {
			_ = tlsConn.Handshake()
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

func TestProbeTLSHealthyCertificate(t *testing.T) {
	cert := selfSignedCert(t, "127.0.0.1", time.Now().AddDate(1, 0, 0))
	port := startTLSTestServer(t, cert, tls.VersionTLS13)

	info := probeTLS("127.0.0.1", port, 2*time.Second, "")
	if info == nil {
		t.Fatal("probeTLS() = nil, want a result")
	}
	if info.Version != "TLS 1.3" {
		t.Errorf("Version = %q, want TLS 1.3", info.Version)
	}
	if info.Weak {
		t.Error("Weak = true for a TLS 1.3 handshake, want false")
	}
	if !info.SelfSigned {
		t.Error("SelfSigned = false, want true (self-issued cert)")
	}
	// A self-signed cert always produces the "self-signed" warning
	// regardless of expiry/hostname, so check that's the *only* one here.
	if len(info.Warnings) != 1 || info.Warnings[0] != "self-signed certificate" {
		t.Errorf("Warnings = %v, want exactly [\"self-signed certificate\"]", info.Warnings)
	}
	// A bare TLS 1.3 listener on this Go toolchain already negotiates a
	// hybrid post-quantum group by default (see CurvePreferences docs), so
	// this handshake is expected to pick one up with no special setup.
	if !info.PQCReady {
		t.Errorf("PQCReady = false, want true (Go 1.26 defaults to a PQC hybrid group on TLS 1.3)")
	}
	if !isPQCGroup(mustParseCurveID(t, info.PQCGroup)) {
		t.Errorf("PQCGroup = %q, want a hybrid post-quantum group name", info.PQCGroup)
	}
}

// mustParseCurveID maps a CurveID.String() name back to its constant so
// tests can assert on isPQCGroup without hardcoding the wire IDs twice.
func mustParseCurveID(t *testing.T, name string) tls.CurveID {
	t.Helper()
	for _, id := range []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521} {
		if id.String() == name {
			return id
		}
	}
	t.Fatalf("mustParseCurveID: unrecognized group name %q", name)
	return 0
}

func TestProbeTLSWarnsWhenNoPQCNegotiated(t *testing.T) {
	cert := selfSignedCert(t, "127.0.0.1", time.Now().AddDate(1, 0, 0))

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519}, // force a classical-only negotiation
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if tlsConn, ok := conn.(*tls.Conn); ok {
			_ = tlsConn.Handshake()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	info := probeTLS("127.0.0.1", port, 2*time.Second, "")
	if info == nil {
		t.Fatal("probeTLS() = nil, want a result")
	}
	if info.PQCReady {
		t.Error("PQCReady = true, want false (server was forced to classical X25519 only)")
	}
	if info.PQCGroup != "X25519" {
		t.Errorf("PQCGroup = %q, want X25519", info.PQCGroup)
	}

	found := false
	for _, w := range info.Warnings {
		if w == "no post-quantum key exchange negotiated (X25519 only)" {
			found = true
		}
	}
	if !found {
		t.Errorf("Warnings = %v, want the no-PQC notice", info.Warnings)
	}
}

func TestIsPQCGroup(t *testing.T) {
	pqc := []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}
	for _, id := range pqc {
		if !isPQCGroup(id) {
			t.Errorf("isPQCGroup(%s) = false, want true", id)
		}
	}

	classical := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	for _, id := range classical {
		if isPQCGroup(id) {
			t.Errorf("isPQCGroup(%s) = true, want false", id)
		}
	}
}

func TestProbeTLSExpiredCertificate(t *testing.T) {
	cert := selfSignedCert(t, "127.0.0.1", time.Now().Add(-24*time.Hour))
	port := startTLSTestServer(t, cert, tls.VersionTLS12)

	info := probeTLS("127.0.0.1", port, 2*time.Second, "")
	if info == nil {
		t.Fatal("probeTLS() = nil, want a result")
	}
	if info.CertDaysLeft >= 0 {
		t.Errorf("CertDaysLeft = %d, want negative (already expired)", info.CertDaysLeft)
	}

	found := false
	for _, w := range info.Warnings {
		if w == "certificate has expired" {
			found = true
		}
	}
	if !found {
		t.Errorf("Warnings = %v, want \"certificate has expired\" present", info.Warnings)
	}
}

func TestProbeTLSExpiringSoonCertificate(t *testing.T) {
	cert := selfSignedCert(t, "127.0.0.1", time.Now().Add(5*24*time.Hour))
	port := startTLSTestServer(t, cert, tls.VersionTLS12)

	info := probeTLS("127.0.0.1", port, 2*time.Second, "")
	if info == nil {
		t.Fatal("probeTLS() = nil, want a result")
	}
	if info.CertDaysLeft < 0 || info.CertDaysLeft >= certExpiryWarnDays {
		t.Errorf("CertDaysLeft = %d, want in [0, %d)", info.CertDaysLeft, certExpiryWarnDays)
	}

	found := false
	for _, w := range info.Warnings {
		if w == "certificate expires in 4 day(s)" || w == "certificate expires in 5 day(s)" {
			found = true
		}
	}
	if !found {
		t.Errorf("Warnings = %v, want an \"expires in N day(s)\" entry", info.Warnings)
	}
}

func TestProbeTLSHostnameMismatch(t *testing.T) {
	cert := selfSignedCert(t, "totally-different-name.example", time.Now().AddDate(1, 0, 0))
	port := startTLSTestServer(t, cert, tls.VersionTLS12)

	info := probeTLS("127.0.0.1", port, 2*time.Second, "")
	if info == nil {
		t.Fatal("probeTLS() = nil, want a result")
	}

	found := false
	for _, w := range info.Warnings {
		if w == "certificate does not match 127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("Warnings = %v, want a hostname-mismatch entry", info.Warnings)
	}
}

func TestProbeTLSVerifiesAgainstHostnameNotIP(t *testing.T) {
	// The regression this guards: a certificate valid for the name the user
	// actually asked for, served by a host reached over an IP that is not in
	// any SAN -- i.e. every name-based virtual host on the internet. Checking
	// the certificate against the IP flagged all of them as mismatched.
	cert := selfSignedCert(t, "secure.example", time.Now().AddDate(1, 0, 0))
	port := startTLSTestServer(t, cert, tls.VersionTLS12)

	info := probeTLS("127.0.0.1", port, 2*time.Second, "secure.example")
	if info == nil {
		t.Fatal("probeTLS() = nil, want a result")
	}

	for _, w := range info.Warnings {
		if strings.HasPrefix(w, "certificate does not match") {
			t.Errorf("Warnings = %v, want no hostname mismatch when verifying against the requested name", info.Warnings)
		}
	}
}

func TestProbeTLSSendsSNI(t *testing.T) {
	// Without SNI a name-based virtual host serves its default certificate,
	// so the probe would report on a certificate the scanned site doesn't
	// even use. Capture what the server actually receives in the ClientHello.
	cert := selfSignedCert(t, "127.0.0.1", time.Now().AddDate(1, 0, 0))

	received := make(chan string, 1)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			select {
			case received <- hello.ServerName:
			default:
			}
			return &cert, nil
		},
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if tlsConn, ok := conn.(*tls.Conn); ok {
			_ = tlsConn.Handshake()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	if info := probeTLS("127.0.0.1", port, 2*time.Second, "vhost.example"); info == nil {
		t.Fatal("probeTLS() = nil, want a result")
	}

	select {
	case got := <-received:
		if got != "vhost.example" {
			t.Errorf("SNI server name = %q, want vhost.example", got)
		}
	case <-time.After(time.Second):
		t.Error("server never saw a ClientHello")
	}
}

func TestProbeTLSWeakVersionIsFlagged(t *testing.T) {
	cert := selfSignedCert(t, "127.0.0.1", time.Now().AddDate(1, 0, 0))
	port := startTLSTestServer(t, cert, tls.VersionTLS11)

	info := probeTLS("127.0.0.1", port, 2*time.Second, "")
	if info == nil {
		t.Fatal("probeTLS() = nil, want a result")
	}
	if !info.Weak {
		t.Error("Weak = false for a TLS 1.1 handshake, want true")
	}

	found := false
	for _, w := range info.Warnings {
		if w == "TLS 1.1 is deprecated/insecure" {
			found = true
		}
	}
	if !found {
		t.Errorf("Warnings = %v, want the TLS 1.1 deprecation notice", info.Warnings)
	}
}

func TestProbeTLSUnreachableReturnsNil(t *testing.T) {
	// Nothing listening on this port -- probeTLS must fail closed (nil),
	// never panic, and never block past the given timeout.
	if info := probeTLS("127.0.0.1", 1, 200*time.Millisecond, ""); info != nil {
		t.Errorf("probeTLS() = %+v for an unreachable port, want nil", info)
	}
}
