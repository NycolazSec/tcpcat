package ai

import (
	"regexp"
	"strings"
	"testing"

	"github.com/NycolazSec/tcpcat/internal/scan"
	"github.com/NycolazSec/tcpcat/internal/service"
)

func TestLocalReason(t *testing.T) {
	for in, want := range map[string]string{
		"SYN-ACK Received":                        "SYN-ACK reçu",
		"SYN-ACK Received (AF_XDP)":               "SYN-ACK reçu (AF_XDP)",
		"RST Received (Closed)":                   "RST reçu (fermé)",
		"UDP Response Received (dns)":             "réponse UDP reçue (dns)",
		"No RST received (RFC 793 Open|Filtered)": "aucun RST reçu (RFC 793 : ouvert ou filtré)",
		"OPEN":                "ouvert",
		"SYN-ACK [Linux 5.x]": "SYN-ACK [Linux 5.x]", // unknown: quoted as is
	} {
		if got := localReason("fr", in); got != want {
			t.Errorf("localReason(%q) = %q, want %q", in, got, want)
		}
		if got := localReason("en", in); got != in {
			t.Errorf("English must stay as the scanner wrote it: %q", got)
		}
	}
}

func TestLocalNote(t *testing.T) {
	for in, want := range map[string]string{
		"weak MAC offered: hmac-sha1, hmac-sha1-96":                           "MAC faible proposé : hmac-sha1, hmac-sha1-96",
		"self-signed certificate":                                             "certificat auto-signé",
		"certificate expires in 12 day(s)":                                    "le certificat expire dans 12 jour(s)",
		"TLS 1.0 is deprecated/insecure":                                      "TLS 1.0 est obsolète et non sûr",
		"also accepts a downgrade to TLS 1.1 (legacy protocol still enabled)": "accepte aussi un retour à TLS 1.1 (ancien protocole encore activé)",
		"something tcpcat may add later":                                      "something tcpcat may add later",
	} {
		if got := localNote("fr", in); got != want {
			t.Errorf("localNote(%q) = %q, want %q", in, got, want)
		}
	}
}

// What the AI says in French has no English left in it, the probes' own
// warnings included.
func TestFrenchFindingsAreFrench(t *testing.T) {
	a := analyzer(t)
	r := open(22, "openssh", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
	r.SSHPosture = &service.SSHPostureInfo{Warnings: []string{"weak key exchange offered: diffie-hellman-group14-sha1"}}
	tls := open(443, "https", "nginx")
	tls.TLS = &service.TLSInfo{Version: "TLS 1.3", Warnings: []string{"self-signed certificate"}}
	rep := a.Analyze([]scan.TargetResult{r, tls}, Options{Lang: "fr", Vantage: Internet})
	english := regexp.MustCompile(`(?i)\b(received|offered|weak|certificate|open)\b`)
	for _, f := range rep.Findings {
		text := strings.Join(append([]string{f.Title, f.Why, f.Fix}, f.Evidence...), " ")
		if m := english.FindString(text); m != "" {
			t.Errorf("port %d: English %q in %q", f.Port, m, text)
		}
	}
}
