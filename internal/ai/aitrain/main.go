// Command aitrain trains the banner model of tcpcat's AI and writes its
// evaluation report.
//
//	git clone --depth 1 https://github.com/rapid7/recog /tmp/recog
//	go run ./internal/ai/aitrain -recog /tmp/recog
//
// Training data: the banner examples of Rapid7 Recog (BSD-2-Clause), framed
// the way each protocol presents them (an SSH example "OpenSSH_9.6" arrives
// as "SSH-2.0-OpenSSH_9.6", a MySQL error as the packet that carries it);
// banners generated from the patterns of Recog's training fingerprints (see
// regexgen.go); the example banners of tcpcat's dictionary; and binary noise
// as examples of "a service the dictionary does not know". Every example is
// degraded under each network condition of internal/ai/model before tcpcat's
// own sanitizer stores it.
//
// Examples are split by fingerprint, not by line, so near-identical
// variants of one fingerprint never sit on both sides of the split: 60% of
// fingerprints train, 20% stop the training and calibrate the confidence,
// 20% are only ever used for the report. Generated banners only come from
// training fingerprints, and the report only judges real ones.
package main

import (
	"encoding/base64"
	"encoding/xml"
	"flag"
	"fmt"
	"hash/fnv"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/NycolazSec/tcpcat/internal/ai/kb"
	"github.com/NycolazSec/tcpcat/internal/ai/model"
	"github.com/NycolazSec/tcpcat/internal/service"
)

type recogFile struct {
	Fingerprints []struct {
		Pattern     string `xml:"pattern,attr"`
		Description string `xml:"description"`
		Examples    []struct {
			Encoding string `xml:"_encoding,attr"`
			Text     string `xml:",chardata"`
		} `xml:"example"`
		Params []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:"value,attr"`
		} `xml:"param"`
	} `xml:"fingerprint"`
}

// source is one Recog database and how its examples reach tcpcat.
type source struct {
	file     string
	protocol string // dictionary ID, or "" for services the dictionary lacks
	frame    func(example string, r *rand.Rand) string
}

func prefix(p string) func(string, *rand.Rand) string {
	return func(e string, _ *rand.Rand) string { return p + e }
}

var sources = []source{
	{"ssh_banners.xml", "ssh", func(e string, r *rand.Rand) string {
		if r.Intn(5) == 0 {
			return "SSH-1.99-" + e
		}
		return "SSH-2.0-" + e
	}},
	{"ftp_banners.xml", "ftp", func(e string, r *rand.Rand) string {
		if r.Intn(4) == 0 {
			return "220-" + e + "\r\n220 ready"
		}
		return "220 " + e
	}},
	{"smtp_banners.xml", "smtp", prefix("220 ")},
	{"pop_banners.xml", "pop3", prefix("+OK ")},
	{"imap_banners.xml", "imap", prefix("* OK ")},
	{"telnet_banners.xml", "telnet", prefix("")},
	{"http_servers.xml", "http", prefix("")},
	{"mysql_banners.xml", "mysql", prefix("")},
	{"rtsp_servers.xml", "rtsp", prefix("")},
	{"mysql_error.xml", "mysql", mysqlError},
	{"nntp_banners.xml", "", prefix("200 ")},
}

// mysqlError wraps an error message in the packet a MySQL server sends to a
// client it refuses before the handshake: length, sequence, 0xff, the error
// code, the text. tcpcat stores what is printable of it.
func mysqlError(e string, r *rand.Rand) string {
	code := 1130 // ER_HOST_NOT_PRIVILEGED
	switch l := strings.ToLower(e); {
	case strings.Contains(l, "block"):
		code = 1129 // ER_HOST_IS_BLOCKED
	case strings.Contains(l, "too many"):
		code = 1040 // ER_CON_COUNT_ERROR
	}
	n := len(e) + 3
	return string([]byte{byte(n), byte(n >> 8), 0, 0, 0xff, byte(code), byte(code >> 8)}) + e
}

// raw is one banner before any network condition.
type raw struct {
	label, banner, group string
	port                 int // conventional port for this label
	fromDictionary       bool
	generated            bool // from a pattern or noise: training only
}

var httpPorts = []int{80, 443, 8080, 8443, 8000}

func main() {
	recogDir := flag.String("recog", "", "Path to a clone of github.com/rapid7/recog")
	out := flag.String("out", "internal/ai/model/weights.bin", "Where to write the model")
	report := flag.String("report", "internal/ai/model/EVALUATION.md", "Where to write the evaluation report")
	seed := flag.Int64("seed", 1, "Random seed")
	epochs := flag.Int("epochs", 30, "Training passes at most (training stops earlier once held-out loss stops improving)")
	rate := flag.Float64("rate", 1, "FTRL learning rate")
	l1 := flag.Float64("l1", 1.5, "L1 regularization (sparser, smaller model)")
	l2 := flag.Float64("l2", 1, "L2 regularization")
	dropout := flag.Float64("dropout", 0.7, "Share of banner features hidden at each pass")
	balance := flag.Float64("balance", 0.5, "0 weighs every example alike, 1 every class alike")
	sweep := flag.Bool("sweep", false, "Print accuracy on the calibration split only (to tune the flags above without looking at the test split)")
	perPattern := flag.Int("generate", 12, "Banners to generate from each training fingerprint's pattern")
	confusion := flag.String("confusion", "", "Print the mistakes on the calibration split under this network condition (clean, unusual-port...)")
	flag.Parse()
	if *recogDir == "" {
		fmt.Fprintln(os.Stderr, "usage: aitrain -recog <path to rapid7/recog>")
		os.Exit(2)
	}
	dict := kb.Default()
	r := rand.New(rand.NewSource(*seed))

	var all []raw
	for _, src := range sources {
		data, err := os.ReadFile(filepath.Join(*recogDir, "xml", src.file))
		if err != nil {
			fail(err)
		}
		var f recogFile
		if err := xml.Unmarshal(data, &f); err != nil {
			fail(fmt.Errorf("%s: %w", src.file, err))
		}
		for i, fp := range f.Fingerprints {
			label := labelFor(dict, src.protocol, product(fp.Params))
			group := fmt.Sprintf("%s#%d", src.file, i)
			seen := map[string]bool{}
			for _, ex := range fp.Examples {
				text := ex.Text
				if ex.Encoding == "base64" {
					b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
					if err != nil {
						continue
					}
					text = string(b)
				}
				if strings.TrimSpace(text) == "" {
					continue
				}
				seen[text] = true
				all = append(all, raw{
					label:  label,
					banner: src.frame(text, r),
					group:  group,
					port:   conventionalPort(dict, label, r),
				})
			}
			if bucket(group) < 2 {
				continue // never generate from a held-out fingerprint
			}
			if g := newGenerator(fp.Pattern); g != nil {
				for k := 0; k < *perPattern; k++ {
					text := g.sample(r)
					if text == "" || seen[text] {
						continue
					}
					seen[text] = true
					all = append(all, raw{label: label, banner: src.frame(text, r), group: group,
						port: conventionalPort(dict, label, r), generated: true})
				}
			}
		}
	}
	// Binary noise: what an unknown binary protocol leaves once tcpcat has
	// kept the printable bytes. The model should say it does not know.
	ports := dict.Ports()
	for k := 0; k < 400; k++ {
		b := make([]byte, 6+r.Intn(60))
		for i := range b {
			b[i] = byte(r.Intn(256))
		}
		if model.Store(string(b)) == "" {
			continue
		}
		port := 1024 + r.Intn(64511)
		if k%2 == 0 {
			port = ports[r.Intn(len(ports))]
		}
		all = append(all, raw{label: model.Other, banner: string(b), group: "noise", port: port, generated: true})
	}
	for _, s := range dict.All() {
		for _, b := range s.Banners {
			all = append(all, raw{label: s.ID, banner: b, group: "dictionary:" + s.ID, port: conventionalPort(dict, s.ID, r), fromDictionary: true})
		}
	}

	var train, calib, test []raw
	for _, e := range all {
		switch {
		case e.fromDictionary || e.generated:
			train = append(train, e)
		case bucket(e.group) == 0:
			test = append(test, e)
		case bucket(e.group) == 1:
			calib = append(calib, e)
		default:
			train = append(train, e)
		}
	}

	degrade := func(set []raw, copies int, r *rand.Rand) []model.Example {
		var out []model.Example
		for _, e := range set {
			n := copies
			if e.fromDictionary {
				n *= 4 // few, hand-checked examples: weigh them more
			}
			for _, c := range model.Conditions {
				label := e.label
				if c.ProtocolOnly {
					label = protocolLabel(dict, label)
				}
				for k := 0; k < n; k++ {
					b, p := c.Apply(e.banner, e.port, r)
					out = append(out, model.Example{Label: label, Banner: model.Store(b), Port: p})
				}
			}
		}
		return out
	}
	trainEx := degrade(train, 1, rand.New(rand.NewSource(*seed+1)))
	calibEx := degrade(calib, 1, rand.New(rand.NewSource(*seed+2)))

	start := time.Now()
	m := model.Train(trainEx, model.TrainOptions{
		Epochs: *epochs, Rate: *rate, L1: *l1, L2: *l2, Dropout: *dropout, Balance: *balance, Seed: *seed, Validate: calibEx,
		Progress: func(epoch int, tl, vl float64) {
			fmt.Fprintf(os.Stderr, "epoch %2d  train loss %.4f  held-out loss %.4f\n", epoch, tl, vl)
		},
	})
	// What ships is the quantized model: calibrate and judge that one.
	data, err := m.Encode()
	if err != nil {
		fail(err)
	}
	if m, err = model.Decode(data); err != nil {
		fail(err)
	}
	m.Calibrate(calibEx)
	gen, noise := countGenerated(all)
	m.Trained = fmt.Sprintf("%s; Rapid7 Recog %s; %d banners (%d generated from its patterns), %d training examples after %d network conditions",
		time.Now().UTC().Format("2006-01-02"), recogCommit(*recogDir), len(all), gen, len(trainEx), len(model.Conditions))
	took := time.Since(start)

	if data, err = m.Encode(); err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		fail(err)
	}

	if *sweep {
		var prot, sureRight, worst float64
		rows := evaluate(dict, m, calib, *seed+3)
		for _, row := range rows {
			prot += row.protocol / float64(len(rows))
			sureRight += row.sureRight / float64(len(rows))
			if row.cond.Name == "worst-case" {
				worst = row.protocol
			}
		}
		fmt.Printf("calibration split: protocol %.2f%%  worst-case %.2f%%  right when sure %.2f%%  size %d KB\n", 100*prot, 100*worst, 100*sureRight, len(data)/1024)
		for _, row := range rows {
			fmt.Printf("  %-13s %.1f%%\n", row.cond.Name, 100*row.protocol)
		}
		return
	}
	if *confusion != "" {
		for _, c := range model.Conditions {
			if c.Name != *confusion {
				continue
			}
			r := rand.New(rand.NewSource(*seed + 3))
			for _, e := range calib { // the test split stays unseen while tuning
				b, p := c.Apply(e.banner, e.port, r)
				stored := model.Store(b)
				if g := m.Classify(stored, p)[0]; protocolOf(dict, g.ID) != protocolOf(dict, e.label) {
					fmt.Printf("%-12s -> %-12s %3.0f%%  %q:%d\n", e.label, g.ID, 100*g.P, stored, p)
				}
			}
		}
		return
	}
	rep := evaluate(dict, m, test, *seed+3)
	var b strings.Builder
	fmt.Fprintf(&b, "# Banner model: evaluation\n\n")
	fmt.Fprintf(&b, "Generated by `go run ./internal/ai/aitrain` on %s. Do not edit by hand.\n\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- Training data: %d banners: %d real ones from Rapid7 Recog %s, %d generated from the patterns of its training fingerprints, %d from tcpcat's dictionary, %d of binary noise; %d classes.\n",
		len(all), len(all)-gen-noise-countDict(all), recogCommit(*recogDir), gen, countDict(all), noise, len(m.Classes))
	fmt.Fprintf(&b, "- Split by fingerprint: %d banners train, %d stop the training and calibrate, %d real banners are held out for this report.\n", len(train), len(calib), len(test))
	fmt.Fprintf(&b, "- Each training banner is degraded under all %d network conditions: %d training examples.\n", len(model.Conditions), len(trainEx))
	fmt.Fprintf(&b, "- Model: multinomial logistic regression over hashed n-grams, words, prefixes, shape and port, %d one-byte weights, %d KB on disk, port weight %.2f, temperature %.2f, trained in %s.\n\n",
		m.Size(), len(data)/1024, m.PortWeight, m.Temperature, took.Round(time.Second))
	b.WriteString("Every held-out banner is degraded under one condition at a time. **Protocol** counts an answer right when it names the right kind of service (SSH, FTP, HTTP...), which is what an exposure decision needs; **exact** also requires the right product (OpenSSH vs Dropbear). **Detector** is tcpcat's existing banner signatures with the port-number fallback, judged on the same protocol criterion. **Sure** is the share of answers with a confidence of 50% or more, and **right when sure** their accuracy.\n\n")
	b.WriteString("| Condition | What it simulates | Protocol | Exact | Detector | Sure | Right when sure |\n|---|---|---:|---:|---:|---:|---:|\n")
	for _, row := range rep {
		exact := fmt.Sprintf("%.1f%%", 100*row.exact)
		if row.cond.ProtocolOnly {
			exact = "n/a"
		}
		fmt.Fprintf(&b, "| %s | %s | %.1f%% | %s | %.1f%% | %.0f%% | %.1f%% |\n", row.cond.Name, row.cond.Why,
			100*row.protocol, exact, 100*row.baseline, 100*row.sure, 100*row.sureRight)
	}
	b.WriteString("\nWhen no banner arrives at all (a filtered port, or a service that waits for the client to speak first), there is nothing to classify: tcpcat's AI then falls back to the dictionary's port conventions and says the identification is unconfirmed.\n")
	if err := os.WriteFile(*report, []byte(b.String()), 0o600); err != nil {
		fail(err)
	}
	fmt.Print(b.String())
}

type row struct {
	cond                                       model.Condition
	protocol, exact, baseline, sure, sureRight float64
}

func evaluate(dict *kb.Dictionary, m *model.Model, test []raw, seed int64) []row {
	var rows []row
	for ci, c := range model.Conditions {
		r := rand.New(rand.NewSource(seed + int64(ci)))
		var n, prot, exact, base, sure, sureRight float64
		for _, e := range test {
			b, p := c.Apply(e.banner, e.port, r)
			stored := model.Store(b)
			want := protocolOf(dict, e.label)
			g := m.Classify(stored, p)[0]
			n++
			if g.ID == e.label {
				exact++
			}
			ok := protocolOf(dict, g.ID) == want
			if ok {
				prot++
			}
			if g.P >= 0.5 {
				sure++
				if ok {
					sureRight++
				}
			}
			name, _ := service.IdentifyStoredBanner(stored, p)
			got := model.Other
			if s := dict.ByName(name); s != nil {
				got = s.Protocol()
			}
			if got == want {
				base++
			}
		}
		rows = append(rows, row{cond: c, protocol: prot / n, exact: exact / n, baseline: base / n, sure: sure / n, sureRight: sureRight / max(sure, 1)})
	}
	return rows
}

func protocolOf(dict *kb.Dictionary, id string) string {
	if s := dict.Get(id); s != nil {
		if s.SpeaksHTTP() {
			return "http" // one kind of service for this comparison: Webmin is a web server
		}
		return s.Protocol()
	}
	return model.Other
}

func product(params []struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}) string {
	for _, want := range []string{"service.product", "service.family"} {
		for _, p := range params {
			if p.Name == want && p.Value != "" {
				return p.Value
			}
		}
	}
	return ""
}

// labelFor names an example by the dictionary entry of its product when
// that product belongs to the protocol the banner came from, and by the
// protocol otherwise (a Dovecot POP3 banner is "pop3": Dovecot's entry
// describes its IMAP service).
func labelFor(dict *kb.Dictionary, protocol, prod string) string {
	if protocol == "" {
		return model.Other
	}
	if prod != "" {
		for _, name := range []string{prod, strings.Fields(prod)[0]} {
			if s := dict.ByName(name); s != nil && (s.Protocol() == protocol || protocol == "http" && s.SpeaksHTTP()) {
				return s.ID
			}
		}
	}
	return protocol
}

func conventionalPort(dict *kb.Dictionary, label string, r *rand.Rand) int {
	s := dict.Get(label)
	for s != nil {
		if len(s.Ports) > 0 {
			return s.Ports[r.Intn(len(s.Ports))]
		}
		if s.Protocol() == "http" || s.Protocol() == "https" {
			return httpPorts[r.Intn(len(httpPorts))]
		}
		if s.Parent == "" || s.Protocol() == s.ID {
			break
		}
		s = dict.Get(s.Protocol())
	}
	return 1024 + r.Intn(64511)
}

func bucket(group string) int {
	h := fnv.New32a()
	h.Write([]byte(group))
	return int(h.Sum32() % 5)
}

func countGenerated(all []raw) (generated, noise int) {
	for _, e := range all {
		switch {
		case e.generated && e.label == model.Other && e.group == "noise":
			noise++
		case e.generated:
			generated++
		}
	}
	return
}

func countDict(all []raw) int {
	n := 0
	for _, e := range all {
		if e.fromDictionary {
			n++
		}
	}
	return n
}

func recogCommit(dir string) string {
	out, err := exec.Command("git", "-C", dir, "log", "-1", "--format=%h (%cs)").Output() // #nosec G204 -- fixed arguments, no shell; dir is the -recog path the developer passed
	if err != nil {
		return "(unknown commit)"
	}
	return strings.TrimSpace(string(out))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "aitrain:", err)
	os.Exit(1)
}

// protocolLabel is the dictionary entry of a label's protocol: "smtp" for
// "postfix". A banner whose product name was replaced can only say that much.
func protocolLabel(dict *kb.Dictionary, label string) string {
	if s := dict.Get(label); s != nil {
		if p := dict.Get(s.Protocol()); p != nil {
			return p.ID
		}
	}
	return label
}
