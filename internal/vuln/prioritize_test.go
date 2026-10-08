package vuln

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestEnricher wires an ExploitEnricher to an httptest server. The handler
// serves "/kev" (CISA KEV catalog shape) and "/epss" (FIRST.org EPSS shape).
func newTestEnricher(t *testing.T, handler http.HandlerFunc) *ExploitEnricher {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &ExploitEnricher{
		client:  &http.Client{Timeout: 5 * time.Second},
		kevURL:  srv.URL + "/kev",
		epssURL: srv.URL + "/epss",
	}
}

// kevAndEPSSHandler serves a fixed KEV set and an EPSS response derived from the
// requested ?cve= list, so a test only has to name which CVEs are "exploited".
func kevAndEPSSHandler(kevCVEs []string, epss map[string][2]string) http.HandlerFunc {
	kevSet := make(map[string]bool, len(kevCVEs))
	for _, c := range kevCVEs {
		kevSet[c] = true
	}
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/kev"):
			var b strings.Builder
			b.WriteString(`{"vulnerabilities":[`)
			for i, c := range kevCVEs {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"cveID":%q}`, c)
			}
			b.WriteString(`]}`)
			_, _ = w.Write([]byte(b.String()))
		case strings.HasPrefix(r.URL.Path, "/epss"):
			requested := strings.Split(r.URL.Query().Get("cve"), ",")
			var b strings.Builder
			b.WriteString(`{"status":"OK","data":[`)
			first := true
			for _, c := range requested {
				vals, ok := epss[c]
				if !ok {
					continue
				}
				if !first {
					b.WriteString(",")
				}
				first = false
				fmt.Fprintf(&b, `{"cve":%q,"epss":%q,"percentile":%q}`, c, vals[0], vals[1])
			}
			b.WriteString(`]}`)
			_, _ = w.Write([]byte(b.String()))
		default:
			http.NotFound(w, r)
		}
	}
}

func TestEnrichTagsKEVAndEPSS(t *testing.T) {
	e := newTestEnricher(t, kevAndEPSSHandler(
		[]string{"CVE-2021-0001"},
		map[string][2]string{
			"CVE-2021-0001": {"0.97000", "0.99900"},
			"CVE-2021-0002": {"0.00042", "0.10000"},
		},
	))

	vulns := []Vulnerability{
		{ID: "CVE-2021-0001", CVSS: 7.5},
		{ID: "CVE-2021-0002", CVSS: 9.8},
		{ID: "RHSA-2021:1234", CVSS: 5.0}, // no CVE -> untouched
	}
	got := e.Enrich(vulns)

	if !got[0].KnownExploited {
		t.Errorf("CVE-2021-0001 should be flagged KnownExploited")
	}
	if got[1].KnownExploited {
		t.Errorf("CVE-2021-0002 should NOT be flagged KnownExploited")
	}
	if got[0].EPSS != 0.97 {
		t.Errorf("CVE-2021-0001 EPSS = %v, want 0.97", got[0].EPSS)
	}
	if got[0].EPSSPercentile != 0.999 {
		t.Errorf("CVE-2021-0001 EPSSPercentile = %v, want 0.999", got[0].EPSSPercentile)
	}
	if got[1].EPSS != 0.00042 {
		t.Errorf("CVE-2021-0002 EPSS = %v, want 0.00042", got[1].EPSS)
	}
	if got[2].KnownExploited || got[2].EPSS != 0 {
		t.Errorf("non-CVE entry should be untouched, got %+v", got[2])
	}
}

func TestEnrichBestEffortOnServerError(t *testing.T) {
	e := newTestEnricher(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	vulns := []Vulnerability{{ID: "CVE-2021-0001", CVSS: 7.5}}
	got := e.Enrich(vulns)

	if len(got) != 1 || got[0].KnownExploited || got[0].EPSS != 0 {
		t.Errorf("on server error the vulns must be returned unchanged, got %+v", got)
	}
}

func TestEnrichNoCVEIDsSkipsNetwork(t *testing.T) {
	called := false
	e := newTestEnricher(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	vulns := []Vulnerability{{ID: "GHSA-xxxx-yyyy-zzzz", CVSS: 6.0}}
	_ = e.Enrich(vulns)

	if called {
		t.Errorf("Enrich must not hit the network when there are no CVE IDs")
	}
}

func TestEnrichDownloadsKEVOnlyOnce(t *testing.T) {
	var kevHits int
	e := newTestEnricher(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/kev") {
			kevHits++
			_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"OK","data":[]}`))
	})

	for i := 0; i < 3; i++ {
		e.Enrich([]Vulnerability{{ID: "CVE-2021-0001"}})
	}
	if kevHits != 1 {
		t.Errorf("KEV catalog fetched %d times, want exactly 1 (cached)", kevHits)
	}
}

func TestPrioritizeExploitability(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "CVE-A", CVSS: 9.8, EPSS: 0.10},                     // high CVSS, low EPSS, no KEV
		{ID: "CVE-B", CVSS: 5.0, EPSS: 0.80},                     // mid CVSS, high EPSS, no KEV
		{ID: "CVE-C", CVSS: 4.0, EPSS: 0.01, KnownExploited: true}, // KEV wins outright
		{ID: "CVE-D", CVSS: 7.0, EPSS: 0.0},                      // tiebreak by CVSS
	}
	PrioritizeExploitability(vulns)

	order := []string{vulns[0].ID, vulns[1].ID, vulns[2].ID, vulns[3].ID}
	want := []string{"CVE-C", "CVE-B", "CVE-A", "CVE-D"}
	for i := range want {
		if order[i] != want[i] {
			t.Errorf("priority order = %v, want %v", order, want)
			break
		}
	}
}

func TestUniqueCVEIDs(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "CVE-2021-0001"},
		{ID: "ALPINE-CVE-2021-0001"}, // same canonical CVE -> deduped
		{ID: "CVE-2021-0002"},
		{ID: "RHSA-2021:1234"}, // no CVE -> skipped
	}
	got := uniqueCVEIDs(vulns)
	want := []string{"CVE-2021-0001", "CVE-2021-0002"}
	if len(got) != len(want) {
		t.Fatalf("uniqueCVEIDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("uniqueCVEIDs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// guard against the enricher hanging a scan if a feed stalls: the client has a
// timeout, and enrichment is best-effort, so a slow server must not block long.
func TestEnrichRespectsClientTimeout(t *testing.T) {
	e := newTestEnricher(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	})
	e.client.Timeout = 200 * time.Millisecond

	done := make(chan struct{})
	go func() {
		e.Enrich([]Vulnerability{{ID: "CVE-2021-0001"}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Enrich did not return promptly despite the client timeout")
	}
}
