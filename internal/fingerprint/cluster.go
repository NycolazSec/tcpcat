// Package fingerprint groups services that service detection could not
// name, so an operator sees "the same unknown service on 230 hosts" instead
// of 230 unrelated "unknown" lines, and gets a ready-to-review banner
// signature for it.
//
// Banners are normalized before grouping: volatile values (numbers, hex
// blobs, IP addresses, host names) become placeholders, so two instances
// of one product that differ only in uptime, session ID or hostname land
// in the same group. The normalized template is also what an export
// carries -- never the raw banner, which can hold internal names.
package fingerprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/NycolazSec/tcpcat/internal/scan"
)

// Placeholders left in a normalized template.
const (
	phIP   = "<ip>"
	phHost = "<host>"
	phHex  = "<hex>"
	phNum  = "<n>"
	phVer  = "<ver>"
)

var (
	reIPv4 = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	reIPv6 = regexp.MustCompile(`\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\b`)
	reHost = regexp.MustCompile(`\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b`)
	reHex  = regexp.MustCompile(`\b(?:0x)?[0-9a-fA-F]{8,}\b`)
	// No leading \b: a version is often glued to a prefix ("v7.3", "OpenSSH_9.6").
	reVersion = regexp.MustCompile(`\d+(?:\.\d+)+[a-z]?\d*\b`)
	reNum     = regexp.MustCompile(`\d+`)
	reSpace   = regexp.MustCompile(`\s+`)
)

// Normalize turns a banner into its template. Order matters: addresses and
// names before versions, versions before bare numbers.
func Normalize(banner string) string {
	s := strings.TrimSpace(banner)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = reIPv4.ReplaceAllString(s, phIP)
	s = reIPv6.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Count(m, ":") >= 2 && len(strings.ReplaceAll(m, ":", "")) >= 2 {
			return phIP
		}
		return m
	})
	s = reHost.ReplaceAllString(s, phHost)
	s = reHex.ReplaceAllString(s, phHex)
	s = reVersion.ReplaceAllString(s, phVer)
	s = reNum.ReplaceAllString(s, phNum)
	s = reSpace.ReplaceAllString(s, " ")
	if len(s) > 160 {
		s = s[:160]
	}
	return strings.TrimSpace(s)
}

type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type Cluster struct {
	Template  string     `json:"template"`
	ID        string     `json:"id"`
	Hosts     int        `json:"hosts"`
	Ports     []int      `json:"ports"`
	Endpoints []Endpoint `json:"-"`
	Samples   []string   `json:"-"`
	// Suggested is a Go signature line for internal/service/signatures.go,
	// to be reviewed (and given a product name) before it is added.
	Suggested string `json:"suggested_signature"`
}

// isUnrecognized: service detection got a banner but no product name.
func isUnrecognized(r scan.TargetResult) bool {
	if r.State != scan.StateOpen || strings.TrimSpace(r.Banner) == "" {
		return false
	}
	switch r.Service {
	case "", "unknown", "ssl/unknown":
		return true
	}
	return false
}

// Group clusters the unrecognized services of a scan, largest first.
func Group(results []scan.TargetResult) []Cluster {
	byTemplate := map[string]*Cluster{}
	hosts := map[string]map[string]bool{}
	for _, r := range results {
		if !isUnrecognized(r) {
			continue
		}
		t := Normalize(r.Banner)
		if t == "" {
			continue
		}
		c, ok := byTemplate[t]
		if !ok {
			c = &Cluster{Template: t, ID: templateID(t)}
			byTemplate[t] = c
			hosts[t] = map[string]bool{}
		}
		c.Endpoints = append(c.Endpoints, Endpoint{IP: r.IP, Port: r.Port})
		if len(c.Samples) < 5 {
			c.Samples = append(c.Samples, strings.TrimSpace(r.Banner))
		}
		hosts[t][r.IP] = true
		if !containsInt(c.Ports, r.Port) {
			c.Ports = append(c.Ports, r.Port)
		}
	}

	clusters := make([]Cluster, 0, len(byTemplate))
	for t, c := range byTemplate {
		c.Hosts = len(hosts[t])
		sort.Ints(c.Ports)
		sort.Slice(c.Endpoints, func(i, j int) bool {
			if c.Endpoints[i].IP != c.Endpoints[j].IP {
				return c.Endpoints[i].IP < c.Endpoints[j].IP
			}
			return c.Endpoints[i].Port < c.Endpoints[j].Port
		})
		c.Suggested = SuggestSignature(c.Template)
		clusters = append(clusters, *c)
	}
	sort.Slice(clusters, func(i, j int) bool {
		if clusters[i].Hosts != clusters[j].Hosts {
			return clusters[i].Hosts > clusters[j].Hosts
		}
		return clusters[i].Template < clusters[j].Template
	})
	return clusters
}

// SuggestSignature turns a template into an anchored regex in the
// bannerSignatures format, capturing the first version placeholder.
func SuggestSignature(template string) string {
	var b strings.Builder
	b.WriteString("^")
	captured := false
	rest := template
	for rest != "" {
		next, ph := nextPlaceholder(rest)
		if next < 0 {
			b.WriteString(regexp.QuoteMeta(rest))
			break
		}
		b.WriteString(regexp.QuoteMeta(rest[:next]))
		switch ph {
		case phVer:
			if !captured {
				b.WriteString(`([\d.]+[a-z]?\d*)`)
				captured = true
			} else {
				b.WriteString(`[\d.]+[a-z]?\d*`)
			}
		case phNum:
			b.WriteString(`\d+`)
		case phHex:
			b.WriteString(`(?:0x)?[0-9a-fA-F]+`)
		case phIP:
			b.WriteString(`[0-9a-fA-F.:]+`)
		case phHost:
			b.WriteString(`[\w.-]+`)
		}
		rest = rest[next+len(ph):]
	}
	pattern := strings.ReplaceAll(b.String(), `\ `, " ")
	pattern = strings.ReplaceAll(pattern, " ", `\s+`)
	return fmt.Sprintf("{\"CHANGE-ME\", regexp.MustCompile(`%s`), false},", pattern)
}

func nextPlaceholder(s string) (int, string) {
	best, which := -1, ""
	for _, ph := range []string{phIP, phHost, phHex, phNum, phVer} {
		if i := strings.Index(s, ph); i >= 0 && (best < 0 || i < best) {
			best, which = i, ph
		}
	}
	return best, which
}

func templateID(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])[:12]
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Export writes the clusters without any address or raw banner: template,
// ID, port numbers and host count only, safe to share with the project to
// help grow the signature set.
func Export(path string, clusters []Cluster) error {
	type entry struct {
		ID        string `json:"id"`
		Template  string `json:"template"`
		Ports     []int  `json:"ports"`
		Hosts     int    `json:"hosts"`
		Suggested string `json:"suggested_signature"`
	}
	out := struct {
		Format   string  `json:"format"`
		Clusters []entry `json:"clusters"`
	}{Format: "tcpcat-fingerprints/v1", Clusters: []entry{}}
	for _, c := range clusters {
		out.Clusters = append(out.Clusters, entry{ID: c.ID, Template: c.Template, Ports: c.Ports, Hosts: c.Hosts, Suggested: c.Suggested})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep "<ver>" readable instead of "\u003cver\u003e"
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0600)
}
