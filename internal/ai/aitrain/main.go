// Command aitrain trains the banner model of tcpcat's AI and writes its
// evaluation report.
//
//	git clone --depth 1 https://github.com/rapid7/recog /tmp/recog
//	go run ./internal/ai/aitrain -recog /tmp/recog
//
// Training data: the banner examples of Rapid7 Recog (BSD-2-Clause), framed
// the way each protocol presents them (an SSH example "OpenSSH_9.6" arrives
// as "SSH-2.0-OpenSSH_9.6"), plus the example banners of tcpcat's
// dictionary. Every example is degraded under each network condition of
// internal/ai/model before tcpcat's own sanitizer stores it.
//
// Examples are split by fingerprint, not by line, so near-identical
// variants of one fingerprint never sit on both sides of the split: 60% of
// fingerprints train, 20% calibrate the confidence, 20% are only ever used
// for the report.
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
	{"nntp_banners.xml", "", prefix("200 ")},
}

// raw is one banner before any network condition.
type raw struct {
	label, banner, group string
	port                 int // conventional port for this label
	fromDictionary       bool
}

var httpPorts = []int{80, 443, 8080, 8443, 8000}

func main() {
	recogDir := flag.String("recog", "", "Path to a clone of github.com/rapid7/recog")
	out := flag.String("out", "internal/ai/model/weights.bin", "Where to write the model")
	report := flag.String("report", "internal/ai/model/EVALUATION.md", "Where to write the evaluation report")
	seed := flag.Int64("seed", 1, "Random seed")
	confusion := flag.Bool("confusion", false, "Print the most frequent mistakes on clean held-out banners")
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
				all = append(all, raw{
					label:  label,
					banner: src.frame(text, r),
					group:  fmt.Sprintf("%s#%d", src.file, i),
					port:   conventionalPort(dict, label, r),
				})
			}
		}
	}
	for _, s := range dict.All() {
		for _, b := range s.Banners {
			all = append(all, raw{label: s.ID, banner: b, group: "dictionary:" + s.ID, port: conventionalPort(dict, s.ID, r), fromDictionary: true})
		}
	}

	var train, calib, test []raw
	for _, e := range all {
		switch {
		case e.fromDictionary:
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
				n *= 6 // few, hand-checked examples: weigh them more
			}
			for _, c := range model.Conditions {
				for k := 0; k < n; k++ {
					b, p := c.Apply(e.banner, e.port, r)
					out = append(out, model.Example{Label: e.label, Banner: model.Store(b), Port: p})
				}
			}
		}
		return out
	}
	trainEx := degrade(train, 1, rand.New(rand.NewSource(*seed+1)))
	calibEx := degrade(calib, 1, rand.New(rand.NewSource(*seed+2)))

	start := time.Now()
	m := model.Train(trainEx, model.TrainOptions{Alpha: 0.05, MinCount: 2})
	m.Calibrate(calibEx)
	m.Trained = fmt.Sprintf("%s; Rapid7 Recog %s; %d raw banners, %d training examples after network conditions",
		time.Now().UTC().Format("2006-01-02"), recogCommit(*recogDir), len(all), len(trainEx))
	took := time.Since(start)

	data, err := m.Encode()
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		fail(err)
	}

	if *confusion {
		mistakes := map[string]int{}
		for _, e := range test {
			stored := model.Store(e.banner)
			if g := m.Classify(stored, e.port)[0]; protocolOf(dict, g.ID) != protocolOf(dict, e.label) {
				mistakes[fmt.Sprintf("%-10s -> %-10s e.g. %q:%d", e.label, g.ID, stored, e.port)]++
			}
		}
		for k := range mistakes {
			fmt.Println(k)
		}
		return
	}
	rep := evaluate(dict, m, test, *seed+3)
	var b strings.Builder
	fmt.Fprintf(&b, "# Banner model: evaluation\n\n")
	fmt.Fprintf(&b, "Generated by `go run ./internal/ai/aitrain` on %s. Do not edit by hand.\n\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- Training data: %d raw banners (%d from Rapid7 Recog %s, %d from tcpcat's dictionary), %d classes.\n",
		len(all), len(all)-countDict(all), recogCommit(*recogDir), countDict(all), len(m.Classes))
	fmt.Fprintf(&b, "- Split by fingerprint: %d banners train, %d calibrate, %d are held out for this report.\n", len(train), len(calib), len(test))
	fmt.Fprintf(&b, "- Each training banner is degraded under all %d network conditions: %d training examples.\n", len(model.Conditions), len(trainEx))
	fmt.Fprintf(&b, "- Model: naive Bayes over hashed character n-grams and words, %d weights, %d KB on disk, temperature %.0f, port weight %.0f, trained in %s.\n\n",
		m.Size(), len(data)/1024, m.Temperature, m.PortWeight, took.Round(time.Millisecond))
	b.WriteString("Every held-out banner is degraded under one condition at a time. **Protocol** counts an answer right when it names the right kind of service (SSH, FTP, HTTP...), which is what an exposure decision needs; **exact** also requires the right product (OpenSSH vs Dropbear). **Detector** is tcpcat's existing banner signatures with the port-number fallback, judged on the same protocol criterion. **Sure** is the share of answers with a confidence of 50% or more, and **right when sure** their accuracy.\n\n")
	b.WriteString("| Condition | What it simulates | Protocol | Exact | Detector | Sure | Right when sure |\n|---|---|---:|---:|---:|---:|---:|\n")
	for _, row := range rep {
		fmt.Fprintf(&b, "| %s | %s | %.1f%% | %.1f%% | %.1f%% | %.0f%% | %.1f%% |\n", row.cond.Name, row.cond.Why,
			100*row.protocol, 100*row.exact, 100*row.baseline, 100*row.sure, 100*row.sureRight)
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
		p := s.Protocol()
		if p == "https" || p == "http-alt" {
			return "http" // one kind of service for this comparison
		}
		return p
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
		if s := dict.ByName(prod); s != nil && s.Protocol() == protocol {
			return s.ID
		}
		if s := dict.ByName(strings.Fields(prod)[0]); s != nil && s.Protocol() == protocol {
			return s.ID
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
