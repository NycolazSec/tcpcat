package service

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// TLSInfo is the result of an independent, read-only TLS handshake probe:
// negotiated protocol version and cipher suite, and what the presented
// certificate says about itself. Populated regardless of the caller's
// --insecure setting -- see probeTLS -- so an invalid/self-signed/expired
// certificate is a *finding* this reports, not a handshake failure that
// silently loses the information.
type TLSInfo struct {
	Version     string `json:"version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	PQCGroup    string `json:"pqc_group,omitempty"`
	// No omitempty: false is the finding an audit is looking for (a target
	// that did NOT negotiate post-quantum key exchange), so it must stay
	// distinguishable from "TLS wasn't probed at all" (the whole TLSInfo is
	// nil) rather than silently vanishing from the JSON like a default would.
	PQCReady      bool     `json:"pqc_ready"`
	CertSubject   string   `json:"cert_subject,omitempty"`
	CertIssuer    string   `json:"cert_issuer,omitempty"`
	CertExpiresAt string   `json:"cert_expires_at,omitempty"`
	CertDaysLeft  int      `json:"cert_days_left,omitempty"`
	// CertCritical marks an expiry warning severe enough to escalate past a
	// routine warning (already expired, or expiring within
	// certExpiryCriticalHours) -- callers printing Warnings can use this to
	// pick a louder color instead of treating every entry the same.
	CertCritical bool `json:"cert_critical,omitempty"`
	// CertSANs is every Subject Alternative Name on the certificate (DNS
	// names and IP addresses alike), shown regardless of whether
	// verification against the scanned host passed -- so a "does not
	// match" warning is never the only information available; the operator
	// can see for themselves what the cert actually covers.
	CertSANs []string `json:"cert_sans,omitempty"`
	SelfSigned bool `json:"self_signed,omitempty"`
	Weak       bool `json:"weak,omitempty"`
	// SupportedVersions lists every TLS version (down to 1.0) the server
	// completes a full handshake with, not just the one it negotiates by
	// default -- a server can default to TLS 1.3 while still happily
	// downgrading for a client that only offers TLS 1.0, which is the real
	// legacy-protocol exposure (see probeSupportedTLSVersions in engine.go's
	// caller).
	SupportedVersions []string `json:"supported_tls_versions,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
}

// certExpiryWarnDays is how close to expiry a certificate has to be before
// probeTLS calls it out as a warning rather than just recording the date.
const certExpiryWarnDays = 14

// certExpiryCriticalHours is how close to expiry escalates the warning from
// routine to critical, and switches its message from a day count (which
// rounds "expires tomorrow" down to a misleadingly calm "0 day(s)") to an
// hour count.
const certExpiryCriticalHours = 48

// probeTLS performs its own dedicated TLS handshake -- separate from the
// one DetectService's HTTP banner grab does on the same port -- specifically
// so it can always set InsecureSkipVerify. This never trusts the connection
// for anything (no data is sent beyond the handshake itself): the whole
// point is to inspect whatever certificate the server presents, including
// self-signed, expired, or hostname-mismatched ones, which is exactly the
// class of finding a security audit wants surfaced rather than swallowed by
// a failed handshake. #nosec G402 -- deliberate, see above.
//
// hostname is the name the target was originally asked for, empty when it
// was given as a bare address. It matters twice: as the SNI sent in the
// ClientHello, without which a name-based virtual host serves its default
// certificate rather than the one actually in use; and as what the
// presented certificate is then checked against, since an IP only matches
// a certificate carrying that IP in a SAN.
func probeTLS(ip string, port int, timeout time.Duration, hostname string) *TLSInfo {
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}

	// MinVersion is set to the oldest version crypto/tls can still speak
	// (TLS 1.0 -- SSLv3 support was removed from the implementation
	// entirely, not just deprecated). Go's own client default floor is
	// TLS 1.2, which would make this handshake simply fail against a
	// server that only offers TLS 1.0/1.1 -- exactly the servers this
	// probe most needs to reach, since failing to connect would silently
	// hide the finding instead of reporting it as weak.
	//
	// ServerName is only carried in the ClientHello here; it never gates
	// the handshake, since InsecureSkipVerify leaves verification to the
	// explicit checks below.
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- deliberate: this probe reports on whatever certificate is presented, valid or not
		MinVersion:         tls.VersionTLS10,
		ServerName:         hostname,
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

	// CurveID is 0 for a legacy RSA key exchange (no group negotiated at
	// all), which isPQCGroup already treats as non-PQC -- but there's
	// nothing meaningful to name in that case, so PQCGroup is left empty
	// rather than reporting "CurveID(0)".
	if state.CurveID != 0 {
		info.PQCGroup = state.CurveID.String()
		info.PQCReady = isPQCGroup(state.CurveID)
		// Go's hybrid post-quantum groups only exist for TLS 1.3; on TLS
		// 1.2 and below this would just repeat the version warning above
		// (or fire on every TLS 1.2 server ever, which isn't a finding).
		if state.Version == tls.VersionTLS13 && !info.PQCReady {
			info.Warnings = append(info.Warnings,
				fmt.Sprintf("no post-quantum key exchange negotiated (%s only)", info.PQCGroup))
		}
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.CertSubject = cert.Subject.CommonName
		info.CertIssuer = cert.Issuer.CommonName
		info.CertExpiresAt = cert.NotAfter.Format("2006-01-02")

		// A Duration comparison, not a floored day count: a cert that
		// expired 2 hours ago has timeLeft < 0 regardless, but
		// int(timeLeft.Hours()/24) truncates toward zero to 0 (not -1),
		// which would misreport a just-expired cert as merely "expiring
		// soon". CertDaysLeft itself keeps the same floored-days value for
		// JSON/XML consumers that already expect a day count.
		timeLeft := time.Until(cert.NotAfter)
		info.CertDaysLeft = int(timeLeft.Hours() / 24)
		switch {
		case timeLeft < 0:
			info.CertCritical = true
			info.Warnings = append(info.Warnings, "CRITICAL: certificate has expired")
		case timeLeft < certExpiryCriticalHours*time.Hour:
			info.CertCritical = true
			info.Warnings = append(info.Warnings,
				fmt.Sprintf("CRITICAL: certificate expires in ~%.0fh", timeLeft.Hours()))
		case info.CertDaysLeft < certExpiryWarnDays:
			info.Warnings = append(info.Warnings, fmt.Sprintf("certificate expires in %d day(s)", info.CertDaysLeft))
		}

		if len(state.PeerCertificates) == 1 && cert.Issuer.String() == cert.Subject.String() {
			info.SelfSigned = true
			info.Warnings = append(info.Warnings, "self-signed certificate")
		}

		info.CertSANs = append(info.CertSANs, cert.DNSNames...)
		for _, sanIP := range cert.IPAddresses {
			info.CertSANs = append(info.CertSANs, sanIP.String())
		}

		verifyAgainst := hostname
		scannedByIP := hostname == ""
		if verifyAgainst == "" {
			verifyAgainst = ip
		}
		if err := cert.VerifyHostname(verifyAgainst); err != nil {
			sansDesc := "none"
			if len(info.CertSANs) > 0 {
				sansDesc = strings.Join(info.CertSANs, ", ")
			}
			if scannedByIP {
				// A certificate covering only a DNS name (the vast
				// majority of them) will always "fail" to verify against
				// whatever bare IP it happened to be reached on -- that's
				// expected, not a misconfiguration, so this stays
				// informational rather than a same-severity warning as a
				// real mismatch (e.g. scanning the wrong hostname).
				info.Warnings = append(info.Warnings,
					fmt.Sprintf("INFO: certificate has no SAN for %s (SANs: %s) -- expected when scanning by IP", verifyAgainst, sansDesc))
			} else {
				info.Warnings = append(info.Warnings,
					fmt.Sprintf("certificate does not match %s (SANs: %s)", verifyAgainst, sansDesc))
			}
		}
	}

	return info
}

// probeSupportedVersionTargets is every TLS version probeSupportedTLSVersions
// tests individually, oldest first.
var probeSupportedVersionTargets = []uint16{
	tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13,
}

// probeSupportedTLSVersions reports which TLS versions the server will
// actually complete a handshake with, one dedicated connection per version
// (MinVersion==MaxVersion pins the client to asking for exactly that one) --
// deliberately separate from probeTLS's own single handshake above, which
// only shows what the server negotiates *by default*. A server can default
// to TLS 1.3 while still accepting a downgrade to TLS 1.0 from a client
// that asks for it, which is the actual legacy-protocol exposure an audit
// cares about, and the default-negotiation handshake alone can't reveal
// that either way.
//
// Each attempt is capped well under the caller's own timeout: a server that
// doesn't support a given version replies with a handshake-failure alert in
// milliseconds, so there's nothing to gain from waiting the full timeout on
// every one of the 4 attempts -- and something real to lose against a
// listener that accepts the TCP connection but never speaks TLS at all
// (dead weight, a non-TLS service on a TLS port), where every attempt would
// otherwise wait out the complete timeout with nothing to show for it.
func probeSupportedTLSVersions(ip string, port int, timeout time.Duration, hostname string) []string {
	attemptTimeout := timeout
	if attemptTimeout > time.Second {
		attemptTimeout = time.Second
	}

	target := net.JoinHostPort(ip, strconv.Itoa(port))
	var supported []string
	for _, version := range probeSupportedVersionTargets {
		dialer := &net.Dialer{Timeout: attemptTimeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- probing which versions the server will accept, not verifying trust
			MinVersion:         version,
			MaxVersion:         version,
			ServerName:         hostname,
		})
		if err != nil {
			continue
		}
		supported = append(supported, tlsVersionName(version))
		_ = conn.Close()
	}
	return supported
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

// isPQCGroup reports whether id is one of the hybrid post-quantum key
// exchange groups crypto/tls offers by default in TLS 1.3 ClientHellos on
// this Go toolchain (X25519MLKEM768 since Go 1.24, the SecP256r1/SecP384r1
// MLKEM hybrids since Go 1.26) rather than a classical elliptic-curve group.
func isPQCGroup(id tls.CurveID) bool {
	switch id {
	case tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024:
		return true
	default:
		return false
	}
}
