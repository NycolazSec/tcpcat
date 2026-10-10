// Package evidence records what a scan observed in a form an auditor can
// check later: a JSON bundle listing every open port with when, from
// where and how it was seen, optionally signed with an Ed25519 key, and a
// replay that re-probes each recorded endpoint to tell whether the finding
// still reproduces or has been fixed.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NycolazSec/tcpcat/internal/scan"
)

const Format = "tcpcat-evidence/v1"

type Bundle struct {
	Format    string    `json:"format"`
	Tool      Tool      `json:"tool"`
	CreatedAt time.Time `json:"created_at"`
	Vantage   Vantage   `json:"vantage"`
	Command   []string  `json:"command"`
	Findings  []Finding `json:"findings"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type Vantage struct {
	Hostname string `json:"hostname"`
}

// Finding is one open port as observed. BannerSHA256 lets a replay detect
// a changed service without the bundle having to carry the full banner.
type Finding struct {
	ID              string   `json:"id"`
	IP              string   `json:"ip"`
	Port            int      `json:"port"`
	State           string   `json:"state"`
	Reason          string   `json:"reason,omitempty"`
	SourceIP        string   `json:"source_ip,omitempty"`
	LatencyMs       float64  `json:"latency_ms"`
	Service         string   `json:"service,omitempty"`
	Version         string   `json:"version,omitempty"`
	Banner          string   `json:"banner,omitempty"`
	BannerSHA256    string   `json:"banner_sha256,omitempty"`
	TLSCert         string   `json:"tls_cert,omitempty"`
	RiskSeverity    string   `json:"risk_severity,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

// maxBanner bounds how much of a banner is kept verbatim (the hash covers
// all of it).
const maxBanner = 512

// sourceIPFor returns the local address the kernel would use to reach ip,
// without sending anything (connecting a UDP socket only selects a route).
func sourceIPFor(ip string) string {
	conn, err := net.Dial("udp", net.JoinHostPort(ip, "9"))
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// FindingID is stable for an endpoint, so a replay or a later bundle can
// refer to the same finding.
func FindingID(ip string, port int) string {
	sum := sha256.Sum256([]byte(net.JoinHostPort(ip, strconv.Itoa(port))))
	return hex.EncodeToString(sum[:])[:12]
}

func BannerHash(banner string) string {
	if banner == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(banner))
	return hex.EncodeToString(sum[:])
}

// Build turns the open ports of a scan into a bundle.
func Build(results []scan.TargetResult, tool Tool, args []string, now time.Time) Bundle {
	host, _ := os.Hostname()
	b := Bundle{
		Format:    Format,
		Tool:      tool,
		CreatedAt: now.UTC(),
		Vantage:   Vantage{Hostname: host},
		Command:   RedactArgs(args),
		Findings:  []Finding{},
	}
	sources := map[string]string{}
	for _, r := range results {
		if r.State != scan.StateOpen {
			continue
		}
		if _, ok := sources[r.IP]; !ok {
			sources[r.IP] = sourceIPFor(r.IP)
		}
		f := Finding{
			ID:           FindingID(r.IP, r.Port),
			IP:           r.IP,
			Port:         r.Port,
			State:        r.State,
			Reason:       r.Reason,
			SourceIP:     sources[r.IP],
			LatencyMs:    r.LatencyMs,
			Service:      r.Service,
			Version:      r.Version,
			Banner:       truncate(r.Banner, maxBanner),
			BannerSHA256: BannerHash(r.Banner),
			RiskSeverity: r.RiskSeverity,
			Notes:        r.Findings,
		}
		if r.TLS != nil && r.TLS.CertSubject != "" {
			f.TLSCert = fmt.Sprintf("%s (issuer %s, expires %s)", r.TLS.CertSubject, r.TLS.CertIssuer, r.TLS.CertExpiresAt)
		}
		for _, v := range r.Vulnerabilities {
			f.Vulnerabilities = append(f.Vulnerabilities, v.ID)
		}
		b.Findings = append(b.Findings, f)
	}
	sort.Slice(b.Findings, func(i, j int) bool {
		if b.Findings[i].IP != b.Findings[j].IP {
			return b.Findings[i].IP < b.Findings[j].IP
		}
		return b.Findings[i].Port < b.Findings[j].Port
	})
	return b
}

// Marshal is the exact byte form that is hashed and signed.
func (b Bundle) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Write stores the bundle, its SHA-256 digest (<path>.sha256, sha256sum
// format) and, when signer is set, an Ed25519 signature (<path>.sig).
func Write(path string, b Bundle, signer *Signer) error {
	data, err := b.Marshal()
	if err != nil {
		return fmt.Errorf("serialize evidence: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	digest := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), baseName(path))
	if err := os.WriteFile(path+".sha256", []byte(digest), 0600); err != nil {
		return err
	}
	if signer != nil {
		if err := os.WriteFile(path+".sig", []byte(signer.Sign(data)+"\n"), 0600); err != nil {
			return err
		}
	}
	return nil
}

// Load reads a bundle and returns it with its raw bytes (for verification).
func Load(path string) (Bundle, []byte, error) {
	var b Bundle
	data, err := os.ReadFile(path)
	if err != nil {
		return b, nil, fmt.Errorf("read evidence: %w", err)
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, nil, fmt.Errorf("parse evidence: %w", err)
	}
	if b.Format != Format {
		return b, nil, fmt.Errorf("unsupported evidence format %q", b.Format)
	}
	return b, data, nil
}

// secretFlags are flags whose value must never land in a shareable bundle.
var secretFlags = []string{"apikey", "webhook", "token", "password", "secret", "key"}

// RedactArgs copies a command line with secret flag values replaced.
func RedactArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	isSecret := func(flagName string) bool {
		name := strings.ToLower(strings.TrimLeft(flagName, "-"))
		for _, s := range secretFlags {
			if strings.Contains(name, s) {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(out); i++ {
		a := out[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		if name, _, hasValue := strings.Cut(a, "="); hasValue {
			if isSecret(name) {
				out[i] = name + "=REDACTED"
			}
			continue
		}
		if isSecret(a) && i+1 < len(out) && !strings.HasPrefix(out[i+1], "-") {
			out[i+1] = "REDACTED"
			i++
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func baseName(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}
