// Package notify posts a short alert to a chat or HTTP webhook when a scan's
// comparison against its baseline finds something new: a newly exposed port, a
// changed service/version, or a newly correlated CVE. Paired with a scheduler
// (cron, a systemd timer) and a state file used as both -j and --baseline, it
// turns tcpcat into a lightweight attack-surface monitor.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NycolazSec/tcpcat/internal/compare"
)

const (
	// maxLines caps how many individual changes are spelled out, so a first
	// run against a stale baseline doesn't post hundreds of lines to a channel.
	maxLines = 20
	// discordContentLimit is Discord's hard limit on a message's content field.
	discordContentLimit = 2000
)

// HasChanges reports whether a comparison found anything worth alerting on.
func HasChanges(r compare.Report) bool {
	return len(r.NewOpenPorts) > 0 || len(r.ServiceChanges) > 0 || len(r.NewVulnerabilities) > 0
}

// Send posts an alert describing r to webhookURL. The payload shape follows the
// destination: Discord webhooks get {"content"}, Slack incoming webhooks get
// {"text"}, and any other URL gets a generic JSON body carrying the text plus
// the full structured comparison for programmatic receivers. Any non-2xx reply
// is returned as an error.
func Send(webhookURL, target string, r compare.Report) error {
	body, err := buildPayload(webhookURL, target, r)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("notify: post webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("notify: webhook returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

func buildPayload(webhookURL, target string, r compare.Report) ([]byte, error) {
	u, err := url.Parse(webhookURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("notify: invalid webhook URL")
	}
	text := FormatText(target, r)
	host := strings.ToLower(u.Hostname())

	var payload any
	switch {
	case host == "discord.com" || host == "discordapp.com" ||
		strings.HasSuffix(host, ".discord.com") || strings.HasSuffix(host, ".discordapp.com"):
		if len(text) > discordContentLimit {
			text = text[:discordContentLimit-4] + "\n…"
		}
		payload = map[string]string{"content": text}
	case host == "hooks.slack.com":
		payload = map[string]string{"text": text}
	default:
		payload = struct {
			Text    string         `json:"text"`
			Target  string         `json:"target"`
			Changes compare.Report `json:"changes"`
		}{Text: text, Target: target, Changes: r}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("notify: encode payload: %w", err)
	}
	return body, nil
}

// FormatText renders r as a short, human-readable chat message.
func FormatText(target string, r compare.Report) string {
	total := len(r.NewOpenPorts) + len(r.ServiceChanges) + len(r.NewVulnerabilities)

	var lines []string
	for _, p := range r.NewOpenPorts {
		lines = append(lines, fmt.Sprintf("• New open port: %s:%d", p.IP, p.Port))
	}
	for _, s := range r.ServiceChanges {
		lines = append(lines, fmt.Sprintf("• Service changed on %s:%d: %s → %s",
			s.IP, s.Port, describe(s.OldService, s.OldVersion), describe(s.NewService, s.NewVersion)))
	}
	for _, v := range r.NewVulnerabilities {
		lines = append(lines, fmt.Sprintf("• New CVE on %s:%d: %s", v.IP, v.Port, v.NewVulnerability))
	}
	if len(lines) > maxLines {
		extra := len(lines) - maxLines
		lines = append(lines[:maxLines], fmt.Sprintf("… and %d more", extra))
	}

	header := fmt.Sprintf("tcpcat: %d change(s) detected on %s", total, target)
	return header + "\n" + strings.Join(lines, "\n")
}

func describe(service, version string) string {
	if service == "" {
		service = "unknown"
	}
	if version == "" {
		return service
	}
	return service + " " + version
}
