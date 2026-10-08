package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A version/banner-based CVE match is only a lead: a host running an affected
// version is not necessarily exploitable, and a list of 50 CVEs sorted by CVSS
// buries the two that matter. Exploit intelligence fixes the ordering by adding
// two real-world signals on top of the static CVSS score:
//
//   - CISA KEV: the Known Exploited Vulnerabilities catalog -- CVEs for which
//     exploitation has actually been observed in the wild. A KEV hit means
//     "patch this first" regardless of CVSS.
//   - EPSS: FIRST.org's Exploit Prediction Scoring System -- a daily-updated
//     probability (0.0-1.0) that a CVE will be exploited in the next 30 days,
//     and its percentile rank among all scored CVEs.
//
// Both are fetched live and are opt-in (tcpcat's --exploit-intel), because they
// add network round-trips to a scan. Enrichment is strictly best-effort: any
// network or decode failure leaves the vulnerabilities untouched rather than
// failing the scan, so a scan run offline simply keeps its CVSS-only ordering.
const (
	defaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	defaultEPSSURL = "https://api.first.org/data/v1/epss"

	// epssBatchSize caps how many CVE IDs go into a single EPSS GET query, so
	// the comma-separated ?cve= list stays well under any reasonable URL-length
	// limit (100 IDs is roughly 1.5 KB) while keeping the request count low.
	epssBatchSize = 100
)

// ExploitEnricher annotates correlated CVEs with KEV and EPSS data. It is safe
// to reuse across many results: the (large) KEV catalog is fetched at most once
// and cached, while EPSS is queried per call for only that call's CVE IDs.
type ExploitEnricher struct {
	client  *http.Client
	kevURL  string
	epssURL string

	kevOnce sync.Once
	kevSet  map[string]struct{}
}

// NewExploitEnricher returns an enricher pointed at the live CISA KEV feed and
// FIRST.org EPSS API, with a generous timeout since the KEV catalog is a few MB.
func NewExploitEnricher() *ExploitEnricher {
	return &ExploitEnricher{
		client:  &http.Client{Timeout: 20 * time.Second},
		kevURL:  defaultKEVURL,
		epssURL: defaultEPSSURL,
	}
}

// Enrich sets KnownExploited/EPSS/EPSSPercentile on every entry whose ID is a
// CVE, in place, and returns the same slice. CVEs that the feeds don't know
// about are left as-is (not an error). The slice is never dropped on failure,
// so callers can always use the return value.
func (e *ExploitEnricher) Enrich(vulns []Vulnerability) []Vulnerability {
	ids := uniqueCVEIDs(vulns)
	if len(ids) == 0 {
		return vulns
	}

	kev := e.kev()
	epss := e.fetchEPSS(ids)

	for i := range vulns {
		id := cveIDPattern.FindString(vulns[i].ID)
		if id == "" {
			continue
		}
		if kev != nil {
			if _, ok := kev[id]; ok {
				vulns[i].KnownExploited = true
			}
		}
		if s, ok := epss[id]; ok {
			vulns[i].EPSS = s.score
			vulns[i].EPSSPercentile = s.percentile
		}
	}
	return vulns
}

// PrioritizeExploitability reorders vulns so the most urgent come first: CVEs
// known to be exploited in the wild (KEV), then by descending EPSS probability,
// then by descending CVSS as the final tiebreak. Stable, so entries that tie on
// all three keep their previous relative order.
func PrioritizeExploitability(vulns []Vulnerability) {
	sort.SliceStable(vulns, func(i, j int) bool {
		if vulns[i].KnownExploited != vulns[j].KnownExploited {
			return vulns[i].KnownExploited
		}
		if vulns[i].EPSS != vulns[j].EPSS {
			return vulns[i].EPSS > vulns[j].EPSS
		}
		return vulns[i].CVSS > vulns[j].CVSS
	})
}

// uniqueCVEIDs returns the distinct canonical CVE IDs present in vulns, in
// first-seen order. Entries whose ID carries no CVE (a vendor errata like an
// RHSA bulletin with no CVE mapping) are skipped: neither feed is keyed by them.
func uniqueCVEIDs(vulns []Vulnerability) []string {
	seen := make(map[string]struct{}, len(vulns))
	var ids []string
	for _, v := range vulns {
		id := cveIDPattern.FindString(v.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

// kev lazily fetches and caches the KEV catalog so a scan that enriches many
// ports downloads the multi-MB feed only once. A failed fetch caches nil, so it
// is not retried for every subsequent port either.
func (e *ExploitEnricher) kev() map[string]struct{} {
	e.kevOnce.Do(func() { e.kevSet = e.fetchKEV() })
	return e.kevSet
}

func (e *ExploitEnricher) fetchKEV() map[string]struct{} {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, e.kevURL, nil)
	if err != nil {
		return nil
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var payload struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}

	set := make(map[string]struct{}, len(payload.Vulnerabilities))
	for _, v := range payload.Vulnerabilities {
		if v.CveID != "" {
			set[v.CveID] = struct{}{}
		}
	}
	return set
}

type epssScore struct {
	score      float64
	percentile float64
}

func (e *ExploitEnricher) fetchEPSS(ids []string) map[string]epssScore {
	out := make(map[string]epssScore, len(ids))
	for start := 0; start < len(ids); start += epssBatchSize {
		end := start + epssBatchSize
		if end > len(ids) {
			end = len(ids)
		}
		e.fetchEPSSBatch(ids[start:end], out)
	}
	return out
}

func (e *ExploitEnricher) fetchEPSSBatch(batch []string, out map[string]epssScore) {
	url := e.epssURL + "?cve=" + strings.Join(batch, ",")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return
	}

	// EPSS reports epss/percentile as JSON strings (e.g. "0.00042"), not
	// numbers, so they are parsed with ParseFloat rather than decoded as
	// float64; an unparseable value just leaves that entry's score at 0.
	var payload struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return
	}
	for _, d := range payload.Data {
		score, _ := strconv.ParseFloat(d.EPSS, 64)
		pct, _ := strconv.ParseFloat(d.Percentile, 64)
		out[d.CVE] = epssScore{score: score, percentile: pct}
	}
}
