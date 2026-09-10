package vuln

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// rewriteTransport redirects every request to target's host, so OSVScanner's
// hardcoded osvApiUrl can be exercised against an httptest.Server.
type rewriteTransport struct {
	target *url.URL
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = t.target.Scheme
	req.URL.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func newTestOSVScanner(t *testing.T, handler http.HandlerFunc) *OSVScanner {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return &OSVScanner{
		client: &http.Client{
			Transport: rewriteTransport{target: target},
			Timeout:   5 * time.Second,
		},
	}
}

func TestOSVScannerSourceName(t *testing.T) {
	if got := NewOSVScanner().SourceName(); got != "OSV API" {
		t.Errorf("SourceName() = %q, want %q", got, "OSV API")
	}
}

func TestOSVScannerGetForSoftwareEmptyArgs(t *testing.T) {
	s := NewOSVScanner()
	got, err := s.GetForSoftware("", "1.0.0")
	if err != nil || got != nil {
		t.Errorf("GetForSoftware with empty software = (%v, %v), want (nil, nil)", got, err)
	}
	got, err = s.GetForSoftware("nginx", "")
	if err != nil || got != nil {
		t.Errorf("GetForSoftware with empty version = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestOSVScannerGetForSoftwareNoVulns(t *testing.T) {
	s := newTestOSVScanner(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(osvResponse{})
	})

	got, err := s.GetForSoftware("nginx", "1.20.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestOSVScannerGetForSoftwareFiltersUnaffectedVersions(t *testing.T) {
	s := newTestOSVScanner(t, func(w http.ResponseWriter, r *http.Request) {
		resp := osvResponse{Vulns: []osvVulnerability{
			{
				ID:      "GHSA-fixed",
				Summary: "fixed before target version",
				Affected: []osvAffected{{Ranges: []osvRange{{Type: "SEMVER", Events: []osvEvent{
					{Introduced: "1.0.0"},
					{Fixed: "1.5.0"},
				}}}}},
			},
			{
				ID:      "GHSA-affected",
				Summary: "still affected at target version",
				Severity: []osvSeverity{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
				Affected: []osvAffected{{Ranges: []osvRange{{Type: "SEMVER", Events: []osvEvent{
					{Introduced: "1.5.0"},
				}}}}},
			},
		}}
		_ = json.NewEncoder(w).Encode(resp)
	})

	got, err := s.GetForSoftware("nginx", "2.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d vulnerabilities, want 1: %+v", len(got), got)
	}
	if got[0].ID != "GHSA-affected" {
		t.Errorf("ID = %q, want GHSA-affected", got[0].ID)
	}
	if got[0].CVSS != 9.8 {
		t.Errorf("CVSS = %v, want 9.8", got[0].CVSS)
	}
}

func TestOSVScannerGetForSoftwareTruncatesLongTitle(t *testing.T) {
	longDetails := strings.Repeat("x", 150)
	s := newTestOSVScanner(t, func(w http.ResponseWriter, r *http.Request) {
		resp := osvResponse{Vulns: []osvVulnerability{
			{ID: "GHSA-long", Details: longDetails},
		}}
		_ = json.NewEncoder(w).Encode(resp)
	})

	got, err := s.GetForSoftware("nginx", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d vulnerabilities, want 1", len(got))
	}
	if len(got[0].Title) != 100 || !strings.HasSuffix(got[0].Title, "...") {
		t.Errorf("Title = %q (len %d), want 100 chars ending in ...", got[0].Title, len(got[0].Title))
	}
}

func TestOSVScannerGetForSoftwareNon200(t *testing.T) {
	s := newTestOSVScanner(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	})

	_, err := s.GetForSoftware("nginx", "1.0.0")
	if err == nil {
		t.Fatal("expected an error for a non-200 response")
	}
}

func TestOSVScannerGetForSoftwareBadJSON(t *testing.T) {
	s := newTestOSVScanner(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})

	_, err := s.GetForSoftware("nginx", "1.0.0")
	if err == nil {
		t.Fatal("expected a decode error for malformed JSON")
	}
}

func TestExtractCVSSScore(t *testing.T) {
	tests := []struct {
		name       string
		severities []osvSeverity
		dbSpecific json.RawMessage
		want       float64
	}{
		{
			name:       "database_specific score takes priority",
			severities: []osvSeverity{{Type: "CVSS_V3", Score: "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}},
			dbSpecific: json.RawMessage(`{"cvss":{"score":7.5}}`),
			want:       7.5,
		},
		{
			name:       "falls back to computing from CVSS_V3 severity vector",
			severities: []osvSeverity{{Type: "CVSS_V3", Score: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			dbSpecific: nil,
			want:       9.8,
		},
		{
			name:       "ignores non-CVSS_V3 severities",
			severities: []osvSeverity{{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:C/I:C/A:C"}},
			dbSpecific: nil,
			want:       0.0,
		},
		{
			name:       "no severity data at all",
			severities: nil,
			dbSpecific: nil,
			want:       0.0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractCVSSScore(tt.severities, tt.dbSpecific); got != tt.want {
				t.Errorf("extractCVSSScore() = %v, want %v", got, tt.want)
			}
		})
	}
}
