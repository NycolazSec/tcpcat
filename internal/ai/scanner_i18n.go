package ai

import (
	"regexp"
	"strings"
)

// The scanner reports why a port is in its state ("SYN-ACK Received") and
// what its probes noticed ("weak MAC offered: hmac-sha1") in English. The AI
// quotes both as evidence, so it translates them; anything it does not
// recognize is quoted as is.

// scanReasons are the scanner's reasons, longest first so that "RST
// Received (Closed)" is not read as "RST Received" followed by "(Closed)".
var scanReasons = [][2]string{
	{"Bypass: ACK->unfiltered, FIN->filtered (implies OPEN)", "contournement : ACK non filtré, FIN filtré (donc ouvert)"},
	{"Bypass: ACK->unfiltered, FIN->closed", "contournement : ACK non filtré, FIN fermé"},
	{"Bypass: Window scan detected closed port", "contournement : le scan Window a vu le port fermé"},
	{"Bypass: Window scan detected open port", "contournement : le scan Window a vu le port ouvert"},
	{"Bypass: Fragmented scan succeeded", "contournement : le scan fragmenté a réussi"},
	{"No RST received (RFC 793 Open|Filtered)", "aucun RST reçu (RFC 793 : ouvert ou filtré)"},
	{"RST received with non-zero window size", "RST reçu avec une fenêtre non nulle"},
	{"RST received with zero window size", "RST reçu avec une fenêtre nulle"},
	{"No response (Stateful Firewall)", "pas de réponse (pare-feu à états)"},
	{"No Response (Timeout)", "pas de réponse (délai dépassé)"},
	{"No response / Timeout", "pas de réponse (délai dépassé)"},
	{"Connection Timeout", "délai de connexion dépassé"},
	{"Connection Refused", "connexion refusée"},
	{"UDP Response Received", "réponse UDP reçue"},
	{"ICMP Port Unreachable", "ICMP port injoignable"},
	{"SYN-ACK Received", "SYN-ACK reçu"},
	{"RST Received", "RST reçu"},
	{"No Response", "pas de réponse"},
	{"Socket Error", "erreur de socket"},
	{"Not probed: AF_XDP transmit queue saturated", "non sondé : file d'envoi AF_XDP saturée"},
	{"Not probed: AF_XDP transmit failed", "non sondé : l'envoi AF_XDP a échoué"},
	{"XDP engine offline", "moteur XDP hors ligne"},
}

var reasonSuffixes = map[string]string{
	"(Closed)":     "(fermé)",
	"(Unfiltered)": "(non filtré)",
}

var portStates = map[string]string{
	"OPEN":          "ouvert",
	"CLOSED":        "fermé",
	"FILTERED":      "filtré",
	"OPEN|FILTERED": "ouvert ou filtré",
	"UNFILTERED":    "non filtré",
}

// localReason translates the scanner's reason for a port's state. What
// follows a known reason ("(AF_XDP)", the UDP probe's name) is kept.
func localReason(lang, reason string) string {
	if lang != "fr" {
		return reason
	}
	if fr, ok := portStates[reason]; ok {
		return fr
	}
	for _, r := range scanReasons {
		if rest, ok := strings.CutPrefix(reason, r[0]); ok {
			rest = strings.TrimSpace(rest)
			if fr, ok := reasonSuffixes[rest]; ok {
				rest = fr
			}
			if rest != "" {
				return r[1] + " " + rest
			}
			return r[1]
		}
	}
	return reason
}

// probeNotes are the probes' warnings and their French form. $1, $2 are
// the parts the warning names (algorithms, a host, a version).
var probeNotes = []struct {
	re *regexp.Regexp
	fr string
}{
	{regexp.MustCompile(`^weak key exchange offered: (.*)$`), "échange de clés faible proposé : $1"},
	{regexp.MustCompile(`^weak MAC offered: (.*)$`), "MAC faible proposé : $1"},
	{regexp.MustCompile(`^weak cipher offered: (.*)$`), "chiffrement faible proposé : $1"},
	{regexp.MustCompile(`^weak host-key algorithm offered: (.*)$`), "algorithme de clé d'hôte faible proposé : $1"},
	{regexp.MustCompile(`^legacy SSH protocol 1\.x offered \(insecure\)$`), "ancien protocole SSH 1.x proposé (non sûr)"},
	{regexp.MustCompile(`^self-signed certificate$`), "certificat auto-signé"},
	{regexp.MustCompile(`^certificate expires in (\d+) day\(s\)$`), "le certificat expire dans $1 jour(s)"},
	{regexp.MustCompile(`^CRITICAL: certificate has expired$`), "CRITIQUE : le certificat a expiré"},
	{regexp.MustCompile(`^CRITICAL: certificate expires in ~(\S+)h$`), "CRITIQUE : le certificat expire dans environ $1 h"},
	{regexp.MustCompile(`^INFO: certificate has no SAN for (\S+) \(SANs: (.*)\) -- expected when scanning by IP$`), "INFO : le certificat n'a pas de SAN pour $1 (SAN : $2), normal quand on scanne par adresse IP"},
	{regexp.MustCompile(`^certificate does not match (\S+) \(SANs: (.*)\)$`), "le certificat ne correspond pas à $1 (SAN : $2)"},
	{regexp.MustCompile(`^no post-quantum key exchange negotiated \((.*) only\)$`), "aucun échange de clés post-quantique négocié ($1 seulement)"},
	{regexp.MustCompile(`^weak cipher suite: (.*)$`), "suite de chiffrement faible : $1"},
	{regexp.MustCompile(`^also accepts a downgrade to (.*) \(legacy protocol still enabled\)$`), "accepte aussi un retour à $1 (ancien protocole encore activé)"},
	{regexp.MustCompile(`^(.*) is deprecated/insecure$`), "$1 est obsolète et non sûr"},
	{regexp.MustCompile(`^missing security header: (.*)$`), "en-tête de sécurité manquant : $1"},
	{regexp.MustCompile(`^MQTT broker accepts anonymous connections$`), "le broker MQTT accepte les connexions anonymes"},
	{regexp.MustCompile(`^SMB dialect negotiated: (.*)$`), "dialecte SMB négocié : $1"},
	{regexp.MustCompile(`^SMB signing is enabled but not required \(a downgrade/relay attack can still disable it\)$`), "la signature SMB est activée mais pas exigée (une attaque par rétrogradation ou par relais peut encore la désactiver)"},
	{regexp.MustCompile(`^SMB signing is not enabled -- sessions are vulnerable to relay/tampering$`), "la signature SMB n'est pas activée : les sessions sont exposées au relais et à la falsification"},
	{regexp.MustCompile(`^SMB signing is required$`), "la signature SMB est exigée"},
	{regexp.MustCompile(`^SMBv1 \(insecure, deprecated since 2014\) is enabled$`), "SMBv1 (non sûr, obsolète depuis 2014) est activé"},
}

// localNote translates one of the probes' warnings.
func localNote(lang, note string) string {
	if lang != "fr" {
		return note
	}
	for _, n := range probeNotes {
		if n.re.MatchString(note) {
			return n.re.ReplaceAllString(note, n.fr)
		}
	}
	return note
}
