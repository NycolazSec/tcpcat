package vuln

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func newTestVulnersScanner(t *testing.T, handler http.HandlerFunc) *VulnersScanner {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return &VulnersScanner{
		apiKey: "test-key",
		httpClient: &http.Client{
			Transport: rewriteTransport{target: target},
			Timeout:   5 * time.Second,
		},
	}
}

func TestNewVulnersScannerRequiresAPIKey(t *testing.T) {
	_, err := NewVulnersScanner("")
	if err == nil {
		t.Fatal("expected an error when apiKey is empty")
	}

	s, err := NewVulnersScanner("abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.apiKey != "abc123" {
		t.Errorf("apiKey = %q, want abc123", s.apiKey)
	}
}

func TestVulnersScannerSourceName(t *testing.T) {
	s, _ := NewVulnersScanner("abc123")
	if got := s.SourceName(); got != "Vulners API" {
		t.Errorf("SourceName() = %q, want Vulners API", got)
	}
}

func TestVulnersScannerGetForSoftwareSuccess(t *testing.T) {
	s := newTestVulnersScanner(t, func(w http.ResponseWriter, r *http.Request) {
		var req vulnersRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Software != "nginx" {
			t.Errorf("request software = %q, want nginx (should be lowercased)", req.Software)
		}

		resp := vulnersResponse{Result: "OK"}
		resp.Data.Search = []struct {
			Source json.RawMessage `json:"_source"`
		}{
			{Source: json.RawMessage(`{"title":"nginx RCE","id":"CVE-2021-0001","cvss":{"score":9.1}}`)},
			{Source: json.RawMessage(`{"title":"no id, should be skipped"}`)},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	got, err := s.GetForSoftware("NGINX", "1.20.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d vulnerabilities, want 1: %+v", len(got), got)
	}
	if got[0].ID != "CVE-2021-0001" || got[0].CVSS != 9.1 {
		t.Errorf("got %+v, want ID=CVE-2021-0001 CVSS=9.1", got[0])
	}
}

func TestVulnersScannerGetForSoftwareAPIError(t *testing.T) {
	s := newTestVulnersScanner(t, func(w http.ResponseWriter, r *http.Request) {
		resp := vulnersResponse{Result: "ERROR"}
		_ = json.NewEncoder(w).Encode(resp)
	})

	_, err := s.GetForSoftware("nginx", "1.20.0")
	if err == nil {
		t.Fatal("expected an error when the API result is not OK")
	}
}

func TestVulnersScannerGetForSoftwareBadJSON(t *testing.T) {
	s := newTestVulnersScanner(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})

	_, err := s.GetForSoftware("nginx", "1.20.0")
	if err == nil {
		t.Fatal("expected a decode error for malformed JSON")
	}
}
