package service

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

// TLSInfo is the result of an independent, read-only TLS handshake probe:
// negotiated protocol version and cipher suite, and what the presented
// certificate says about itself. Populated regardless of the caller's
// --insecure setting -- see probeTLS -- so an invalid/self-signed/expired
// certificate is a *finding* this reports, not a handshake failure that
// silently loses the information.
type TLSInfo struct {
	Version       string   `json:"version,omitempty"`
	CipherSuite   string   `json:"cipher_suite,omitempty"`
	CertSubject   string   `json:"cert_subject,omitempty"`
	CertIssuer    string   `json:"cert_issuer,omitempty"`
	CertExpiresAt string   `json:"cert_expires_at,omitempty"`
	CertDaysLeft  int      `json:"cert_days_left,omitempty"`
	SelfSigned    bool     `json:"self_signed,omitempty"`
	Weak          bool     `json:"weak,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
}

// certExpiryWarnDays is how close to expiry a certificate has to be before
// probeTLS calls it out as a warning rather than just recording the date.
const certExpiryWarnDays = 14

// probeTLS performs its own dedicated TLS handshake -- separate from the
// one DetectService's HTTP banner grab does on the same port -- specifically
// so it can always set InsecureSkipVerify. This never trusts the connection
// for anything (no data is sent beyond the handshake itself): the whole
// point is to inspect whatever certificate the server presents, including
// self-signed, expired, or hostname-mismatched ones, which is exactly the
// class of finding a security audit wants surfaced rather than swallowed by
// a failed handshake. #nosec G402 -- deliberate, see above.
func probeTLS(ip string, port int, timeout time.Duration) *TLSInfo {
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}

	// MinVersion is set to the oldest version crypto/tls can still speak
	// (TLS 1.0 -- SSLv3 support was removed from the implementation
	// entirely, not just deprecated). Go's own client default floor is
	// TLS 1.2, which would make this handshake simply fail against a
	// server that only offers TLS 1.0/1.1 -- exactly the servers this
	// probe most needs to reach, since failing to connect would silently
	// hide the finding instead of reporting it as weak.
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- deliberate: this probe reports on whatever certificate is presented, valid or not
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()
	info := &TLSInfo{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}

	if isWeakTLSVersion(state.Version) {
		info.Weak = true
		info.Warnings = append(info.Warnings, fmt.Sprintf("%s is deprecated/insecure", info.Version))
	}
	if isWeakCipherSuite(state.CipherSuite) {
		info.Weak = true
		info.Warnings = append(info.Warnings, fmt.Sprintf("weak cipher suite: %s", info.CipherSuite))
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.CertSubject = cert.Subject.CommonName
		info.CertIssuer = cert.Issuer.CommonName
		info.CertExpiresAt = cert.NotAfter.Format("2006-01-02")

		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		info.CertDaysLeft = daysLeft
		switch {
		case daysLeft < 0:
			info.Warnings = append(info.Warnings, "certificate has expired")
		case daysLeft < certExpiryWarnDays:
			info.Warnings = append(info.Warnings, fmt.Sprintf("certificate expires in %d day(s)", daysLeft))
		}

		if len(state.PeerCertificates) == 1 && cert.Issuer.String() == cert.Subject.String() {
			info.SelfSigned = true
			info.Warnings = append(info.Warnings, "self-signed certificate")
		}

		if err := cert.VerifyHostname(ip); err != nil {
			info.Warnings = append(info.Warnings, "certificate does not match target hostname/IP")
		}
	}

	return info
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func isWeakTLSVersion(version uint16) bool {
	return version < tls.VersionTLS12
}

func isWeakCipherSuite(id uint16) bool {
	for _, c := range tls.InsecureCipherSuites() {
		if c.ID == id {
			return true
		}
	}
	return false
}
