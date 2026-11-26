package model

import (
	"math/rand"
	"strings"
)

// A Condition degrades a raw banner the way a real network path can, before
// tcpcat stores it. The model is trained on every condition and evaluated on
// each one separately, so a weakness shows up under its own name instead of
// hiding in an average.
type Condition struct {
	Name string
	// Label names it for people, in English and French.
	Label [2]string
	// Why is shown in the evaluation report.
	Why   string
	Apply func(raw string, port int, r *rand.Rand) (string, int)
	// ProtocolOnly conditions remove what names the product: an example
	// degraded by one is labelled with its protocol only, and only the
	// protocol is judged.
	ProtocolOnly bool
}

// Store is what tcpcat keeps of a raw banner: carriage returns dropped, line
// feeds turned into spaces, control and non-ASCII bytes removed, and the
// result cut to 60 characters. It mirrors internal/service's sanitizer; the
// test in conditions_test.go keeps the two in step.
var Store = func(raw string) string {
	cleaned := strings.ReplaceAll(raw, "\r", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", " ")
	var b strings.Builder
	for i := 0; i < len(cleaned); i++ {
		if c := cleaned[i]; c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
		}
	}
	s := b.String()
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

// Conditions are the network conditions the model is trained and judged on.
var Conditions = []Condition{
	{
		Name:  "clean",
		Label: [2]string{"whole banner", "bannière complète"},
		Why:   "the whole banner arrived",
		Apply: func(raw string, port int, _ *rand.Rand) (string, int) { return raw, port },
	},
	{
		Name:  "truncated",
		Label: [2]string{"cut by a timeout", "coupée par un délai"},
		Why:   "slow or lossy link: the read deadline expired mid-banner (40-90% kept)",
		Apply: truncate,
	},
	{
		Name:  "first-bytes",
		Label: [2]string{"first bytes only", "premiers octets seulement"},
		Why:   "only the first few bytes made it before the timeout (8-20 bytes)",
		Apply: func(raw string, port int, r *rand.Rand) (string, int) {
			keep := 8 + r.Intn(13)
			if keep < len(raw) {
				raw = raw[:keep]
			}
			return raw, port
		},
	},
	{
		Name:  "noise",
		Label: [2]string{"binary noise around it", "bruit binaire autour"},
		Why:   "negotiation or binary bytes around the text (Telnet IAC, framing, middleboxes)",
		Apply: addNoise,
	},
	{
		Name:  "reformatted",
		Label: [2]string{"reformatted", "reformatée"},
		Why:   "different line endings, padding or letter case from the same software",
		Apply: func(raw string, port int, r *rand.Rand) (string, int) {
			switch r.Intn(4) {
			case 0:
				raw = strings.ToUpper(raw)
			case 1:
				raw = strings.ReplaceAll(raw, " ", "  ")
			case 2:
				raw = raw + "\r\n"
			default:
				raw = "  " + raw + " \t"
			}
			return raw, port
		},
	},
	{
		Name:  "unusual-port",
		Label: [2]string{"unusual port", "port inhabituel"},
		Why:   "the service listens on a non-standard port (SSH on 2222, a web app on 9443...)",
		Apply: func(raw string, port int, r *rand.Rand) (string, int) {
			return raw, randomPort(r)
		},
	},
	{
		Name:         "rebranded",
		Label:        [2]string{"product name replaced", "nom du produit remplacé"},
		Why:          "the administrator or vendor replaced the product name (a custom SSH version string, a hostname-only SMTP greeting, a home-made Server header)",
		Apply:        rebrand,
		ProtocolOnly: true,
	},
	{
		Name:  "pipelined",
		Label: [2]string{"server keeps talking", "le serveur continue de parler"},
		Why:   "the server kept talking in the same read: the SSH key exchange right after the banner, a multi-line greeting that starts with a legal notice",
		Apply: pipeline,
	},
	{
		Name:  "worst-case",
		Label: [2]string{"cut, noisy, unusual port", "coupée, bruitée, port inhabituel"},
		Why:   "truncated, noisy and on an unusual port at once",
		Apply: func(raw string, port int, r *rand.Rand) (string, int) {
			raw, _ = truncate(raw, port, r)
			raw, _ = addNoise(raw, port, r)
			return raw, randomPort(r)
		},
	},
}

const printableJunk = "!\"#$%&'*+-.:;<=>?@[]^_{|}~"

// commonAltPorts are non-standard ports services are often moved to.
var commonAltPorts = []int{2222, 2022, 8022, 2121, 2525, 8025, 8080, 8443, 8888, 9443, 10022, 4443, 3307, 5433, 6380, 27018}

func randomPort(r *rand.Rand) int {
	if r.Intn(2) == 0 {
		return commonAltPorts[r.Intn(len(commonAltPorts))]
	}
	return 1024 + r.Intn(64511)
}

func truncate(raw string, port int, r *rand.Rand) (string, int) {
	if len(raw) <= 8 {
		return raw, port
	}
	keep := int(float64(len(raw)) * (0.4 + 0.5*r.Float64()))
	if keep < 6 {
		keep = 6
	}
	return raw[:keep], port
}

func addNoise(raw string, port int, r *rand.Rand) (string, int) {
	junk := func() string {
		var b strings.Builder
		for i, n := 0, 1+r.Intn(5); i < n; i++ {
			switch r.Intn(3) {
			case 0:
				b.WriteByte(byte(r.Intn(32))) // control byte: stripped on store
			case 1:
				b.WriteByte(0xff) // Telnet IAC: stripped on store
			default:
				b.WriteByte(printableJunk[r.Intn(len(printableJunk))])
			}
		}
		return b.String()
	}
	switch r.Intn(3) {
	case 0:
		return junk() + raw, port
	case 1:
		return raw + junk(), port
	default:
		return junk() + raw + junk(), port
	}
}

// keepWords are a protocol's own words, which a rebranded banner keeps.
var keepWords = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`ssh sftp ftp ftpd smtp esmtp lmtp pop imap imapd mail mailer server servers
		service services ready welcome login user username password http httpd www web rtsp telnet version
		access verification authorized unauthorized system the and for are you not has been this with your
		auth capability capabilities starttls imap rev plain connection port host network closing gateway
		protocol transmission channel please enter account name use only prohibited monitored`) {
		keepWords[w] = true
	}
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// rebrand replaces the words that are not the protocol's own with made-up
// ones of the same length and case.
func rebrand(raw string, port int, r *rand.Rand) (string, int) {
	var b strings.Builder
	for i := 0; i < len(raw); {
		if !isLetter(raw[i]) {
			b.WriteByte(raw[i])
			i++
			continue
		}
		j := i
		for j < len(raw) && isLetter(raw[j]) {
			j++
		}
		w := raw[i:j]
		if len(w) >= 3 && !keepWords[strings.ToLower(w)] {
			w = pseudoWord(w, r)
		}
		b.WriteString(w)
		i = j
	}
	return b.String(), port
}

func pseudoWord(like string, r *rand.Rand) string {
	const consonants, vowels = "bcdfghjklmnprstvz", "aeiou"
	out := make([]byte, len(like))
	for i := range out {
		set := consonants
		if i%2 == 1 {
			set = vowels
		}
		c := set[r.Intn(len(set))]
		if like[i] >= 'A' && like[i] <= 'Z' {
			c -= 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

var legalNotices = []string{
	"Authorized users only. All activity may be monitored and reported.",
	"Welcome to the file server of example.org",
	"This system is for the use of authorized users only.",
	"----------- Welcome -----------",
	"Unauthorized access is prohibited",
	"mail.example.com",
}

var kexAlgorithms = []string{
	"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384",
	"sntrup761x25519-sha512@openssh.com,curve25519-sha256,ecdh-sha2-nistp256",
	"mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256",
	"diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,ext-info-s",
}

// pipeline appends what a server sends right after its banner when it does
// not wait for the client: the binary SSH_MSG_KEXINIT after an SSH version,
// a capability line after an IMAP greeting; or puts a notice before a
// multi-line FTP or SMTP greeting, so the product may fall past what tcpcat
// keeps.
func pipeline(raw string, port int, r *rand.Rand) (string, int) {
	switch {
	case strings.HasPrefix(raw, "SSH-"):
		var b strings.Builder
		b.WriteString(raw + "\r\n")
		b.Write([]byte{0, 0, 4, byte(r.Intn(256)), byte(4 + r.Intn(8)), 20})
		for i := 0; i < 16; i++ {
			b.WriteByte(byte(r.Intn(256))) // the random cookie
		}
		kex := kexAlgorithms[r.Intn(len(kexAlgorithms))]
		b.Write([]byte{0, 0, 0, byte(len(kex))})
		b.WriteString(kex)
		return b.String(), port
	case strings.HasPrefix(raw, "220"):
		lines := 1 + r.Intn(2)
		var b strings.Builder
		for i := 0; i < lines; i++ {
			b.WriteString("220-" + legalNotices[r.Intn(len(legalNotices))] + "\r\n")
		}
		return b.String() + raw, port
	case strings.HasPrefix(raw, "* OK"):
		return raw + "\r\n* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN", port
	}
	return raw, port
}
