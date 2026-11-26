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
	// Why is shown in the evaluation report.
	Why   string
	Apply func(raw string, port int, r *rand.Rand) (string, int)
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
		Why:   "the whole banner arrived",
		Apply: func(raw string, port int, _ *rand.Rand) (string, int) { return raw, port },
	},
	{
		Name:  "truncated",
		Why:   "slow or lossy link: the read deadline expired mid-banner (40-90% kept)",
		Apply: truncate,
	},
	{
		Name: "first-bytes",
		Why:  "only the first few bytes made it before the timeout (8-20 bytes)",
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
		Why:   "negotiation or binary bytes around the text (Telnet IAC, framing, middleboxes)",
		Apply: addNoise,
	},
	{
		Name: "reformatted",
		Why:  "different line endings, padding or letter case from the same software",
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
		Name: "unusual-port",
		Why:  "the service listens on a non-standard port (SSH on 2222, a web app on 9443...)",
		Apply: func(raw string, port int, r *rand.Rand) (string, int) {
			return raw, randomPort(r)
		},
	},
	{
		Name: "worst-case",
		Why:  "truncated, noisy and on an unusual port at once",
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
