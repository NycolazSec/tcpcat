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

func TestOSVScannerGetForSoftwareDedupesSameCVEAcrossVendorFeeds(t *testing.T) {
	// Real OSV traffic for a single piece of software routinely restates
	// the same underlying CVE under several vendor-specific IDs -- one
	// folding the CVE straight into its own ID (Alpine), another carrying
	// it only in its alias list (OSV's own "BIT-" feed) -- which used to
	// come back as duplicate, unlabeled rows instead of one real finding.
	s := newTestOSVScanner(t, func(w http.ResponseWriter, r *http.Request) {
		resp := osvResponse{Vulns: []osvVulnerability{
			{
				ID:      "ALPINE-CVE-2016-10009",
				Summary: "",
				Severity: []osvSeverity{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
			},
			{
				ID:      "BIT-openssh-2016-10009",
				Aliases: []string{"CVE-2016-10009"},
				Summary: "OpenSSH ssh-agent search path issue",
			},
		}}
		_ = json.NewEncoder(w).Encode(resp)
	})

	got, err := s.GetForSoftware("openssh", "6.6.1p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d vulnerabilities, want 1 (deduped): %+v", len(got), got)
	}
	if got[0].ID != "CVE-2016-10009" {
		t.Errorf("ID = %q, want CVE-2016-10009", got[0].ID)
	}
	// The first occurrence had no title but the CVSS; the second had the
	// title but no CVSS -- the merged row should carry both.
	if got[0].Title != "OpenSSH ssh-agent search path issue" {
		t.Errorf("Title = %q, want the title from the second (aliased) entry", got[0].Title)
	}
	if got[0].CVSS != 9.8 {
		t.Errorf("CVSS = %v, want 9.8 from the first entry", got[0].CVSS)
	}
}

func TestOSVScannerGetForSoftwareKeepsRawIDWhenNoCVEMapping(t *testing.T) {
	// A vendor errata bulletin with no CVE anywhere (id or aliases) has
	// nothing to normalize to, so it must still surface under its own
	// native ID rather than being dropped.
	s := newTestOSVScanner(t, func(w http.ResponseWriter, r *http.Request) {
		resp := osvResponse{Vulns: []osvVulnerability{
			{ID: "MGASA-2020-0123", Summary: "Mageia security advisory with no CVE mapping"},
		}}
		_ = json.NewEncoder(w).Encode(resp)
	})

	got, err := s.GetForSoftware("apache", "2.4.7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].ID != "MGASA-2020-0123" {
		t.Errorf("got %+v, want a single entry with ID MGASA-2020-0123", got)
	}
}

func TestCanonicalCVEID(t *testing.T) {
	tests := []struct {
		name string
		v    osvVulnerability
		want string
	}{
		{"CVE embedded in the id itself", osvVulnerability{ID: "ALPINE-CVE-2016-10009"}, "CVE-2016-10009"},
		{"CVE only in aliases", osvVulnerability{ID: "BIT-apache-2020-11985", Aliases: []string{"CVE-2020-11985"}}, "CVE-2020-11985"},
		{"id wins over a different aliased CVE", osvVulnerability{ID: "DEBIAN-CVE-2000-0992", Aliases: []string{"CVE-1999-9999"}}, "CVE-2000-0992"},
		{"no CVE anywhere falls back to the raw id", osvVulnerability{ID: "MGASA-2020-0123", Aliases: []string{"MGASA-2020-0123"}}, "MGASA-2020-0123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canonicalCVEID(tt.v); got != tt.want {
				t.Errorf("canonicalCVEID(%+v) = %q, want %q", tt.v, got, tt.want)
			}
		})
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
		affected   []osvAffected
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
		{
			// The Bitnami vulndb import ("BIT-*" OSV IDs) is the only CVSS
			// source for a large share of real-world results (see the
			// package-level comment on extractCVSSScore) and keeps its
			// vector under affected[].severity instead of the top level.
			name:       "falls back to affected[].severity when nothing else has it",
			severities: nil,
			dbSpecific: json.RawMessage(`{"cpes":["cpe:2.3:a:apache:http_server:*"],"severity":"High"}`),
			affected: []osvAffected{{
				Severity: []osvSeverity{{Type: "CVSS_V3", Score: "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"}},
			}},
			want: 7.5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractCVSSScore(tt.severities, tt.dbSpecific, tt.affected); got != tt.want {
				t.Errorf("extractCVSSScore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOSVScannerGetForDistroPackageSendsEcosystem(t *testing.T) {
	var gotQuery osvQuery
	s := newTestOSVScanner(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotQuery)
		resp := osvResponse{Vulns: []osvVulnerability{
			{
				ID: "DEBIAN-CVE-2024-21096",
				Affected: []osvAffected{{Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{
					{Introduced: "0"},
					{Fixed: "1:10.11.11-0+deb12u1"},
				}}}}},
			},
		}}
		_ = json.NewEncoder(w).Encode(resp)
	})

	got, err := s.GetForDistroPackage(DistroPackage{Ecosystem: "Debian:12", Name: "mariadb", Version: "1:10.11.6-0+deb12u1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotQuery.Package.Ecosystem != "Debian:12" || gotQuery.Package.Name != "mariadb" {
		t.Errorf("query sent package = %+v, want ecosystem=Debian:12 name=mariadb", gotQuery.Package)
	}
	if len(got) != 1 || got[0].ID != "CVE-2024-21096" {
		t.Errorf("got %+v, want a single CVE-2024-21096 result", got)
	}
}

func TestOSVScannerGetForDistroPackageEmptyArgs(t *testing.T) {
	s := NewOSVScanner()
	for _, pkg := range []DistroPackage{
		{Name: "", Version: "1.0", Ecosystem: "Debian:12"},
		{Name: "x", Version: "", Ecosystem: "Debian:12"},
		{Name: "x", Version: "1.0", Ecosystem: ""},
	} {
		if got, err := s.GetForDistroPackage(pkg); err != nil || got != nil {
			t.Errorf("GetForDistroPackage(%+v) = (%v, %v), want (nil, nil)", pkg, got, err)
		}
	}
}
