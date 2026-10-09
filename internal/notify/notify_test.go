package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NycolazSec/tcpcat/internal/compare"
)

func sampleReport() compare.Report {
	return compare.Report{
		NewOpenPorts: []compare.PortChange{{IP: "10.0.0.1", Port: 8080}},
		ServiceChanges: []compare.ServiceChange{{
			IP: "10.0.0.1", Port: 22,
			OldService: "openssh", OldVersion: "7.4",
			NewService: "openssh", NewVersion: "9.6",
		}},
		NewVulnerabilities: []compare.VulnerabilityChange{{IP: "10.0.0.1", Port: 22, NewVulnerability: "CVE-2024-6387"}},
	}
}

func TestHasChanges(t *testing.T) {
	if HasChanges(compare.Report{}) {
		t.Errorf("empty report should have no changes")
	}
	if !HasChanges(sampleReport()) {
		t.Errorf("sample report should have changes")
	}
}

func TestFormatText(t *testing.T) {
	text := FormatText("10.0.0.0/24", sampleReport())
	for _, want := range []string{
		"3 change(s) detected on 10.0.0.0/24",
		"New open port: 10.0.0.1:8080",
		"openssh 7.4 → openssh 9.6",
		"New CVE on 10.0.0.1:22: CVE-2024-6387",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q:\n%s", want, text)
		}
	}
}

func TestFormatTextCapsLines(t *testing.T) {
	var r compare.Report
	for i := 0; i < 30; i++ {
		r.NewOpenPorts = append(r.NewOpenPorts, compare.PortChange{IP: "10.0.0.1", Port: 1000 + i})
	}
	text := FormatText("t", r)
	if !strings.Contains(text, "… and 10 more") {
		t.Errorf("expected overflow line, got:\n%s", text)
	}
	if strings.Count(text, "New open port") != maxLines {
		t.Errorf("expected exactly %d spelled-out changes", maxLines)
	}
}

func TestBuildPayloadShapes(t *testing.T) {
	r := sampleReport()

	tests := []struct {
		url     string
		wantKey string
		notKey  string
	}{
		{"https://discord.com/api/webhooks/1/abc", "content", "text"},
		{"https://discordapp.com/api/webhooks/1/abc", "content", "text"},
		{"https://hooks.slack.com/services/T/B/X", "text", "content"},
		{"https://example.internal/hook", "changes", "content"},
	}
	for _, tt := range tests {
		body, err := buildPayload(tt.url, "t", r)
		if err != nil {
			t.Fatalf("%s: %v", tt.url, err)
		}
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("%s: invalid JSON: %v", tt.url, err)
		}
		if _, ok := m[tt.wantKey]; !ok {
			t.Errorf("%s: payload missing %q: %s", tt.url, tt.wantKey, body)
		}
		if _, ok := m[tt.notKey]; ok {
			t.Errorf("%s: payload should not carry %q: %s", tt.url, tt.notKey, body)
		}
	}
}

func TestBuildPayloadTruncatesForDiscord(t *testing.T) {
	var r compare.Report
	for i := 0; i < 20; i++ {
		r.NewVulnerabilities = append(r.NewVulnerabilities, compare.VulnerabilityChange{
			IP: "10.0.0.1", Port: 22, NewVulnerability: strings.Repeat("X", 150),
		})
	}
	body, err := buildPayload("https://discord.com/api/webhooks/1/abc", "t", r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	_ = json.Unmarshal(body, &m)
	if n := len(m["content"]); n > discordContentLimit {
		t.Errorf("Discord content is %d bytes, over the %d limit", n, discordContentLimit)
	}
}

func TestBuildPayloadRejectsBadURL(t *testing.T) {
	if _, err := buildPayload("not a url", "t", sampleReport()); err == nil {
		t.Errorf("expected an error for an invalid webhook URL")
	}
}

func TestSendPostsJSON(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &got)
		w.WriteHeader(http.StatusNoContent) // Discord answers 204
	}))
	defer srv.Close()

	if err := Send(srv.URL+"/hook", "10.0.0.0/24", sampleReport()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got["target"] != "10.0.0.0/24" || got["changes"] == nil {
		t.Errorf("generic payload not received as expected: %v", got)
	}
}

func TestSendReportsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := Send(srv.URL, "t", sampleReport())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected a 401 error, got %v", err)
	}
}
