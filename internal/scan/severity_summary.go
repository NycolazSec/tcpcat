package scan

import "sort"

// SeveritySummaryEntry is one severity tier's aggregate across a scan: how
// many vulnerabilities were found at that tier, and which distinct hosts
// they were found on.
type SeveritySummaryEntry struct {
	Severity string   `json:"severity"`
	Count    int      `json:"count"`
	Hosts    []string `json:"hosts"`
}

// severityOrder is triage order (critical first) -- not alphabetical,
// which iterating a map or a generic sort would give instead.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// SummarizeSeverity aggregates the vulnerabilities across results by
// severity tier, each with the sorted, deduplicated list of hosts it was
// found on. Entries flagged as not applicable (another OS, a component the
// scan cannot confirm, a client-only flaw: see vuln.AnnotateApplicability)
// are left out, as they are from each host's headline risk. Tiers with zero
// findings are omitted entirely. Meant to be
// computed once at the end of a scan and reused for the console summary,
// the JSON report, and the SARIF report, rather than each recomputing it.
func SummarizeSeverity(results []TargetResult) []SeveritySummaryEntry {
	hostsBySeverity := map[string]map[string]bool{}
	countBySeverity := map[string]int{}

	for _, r := range results {
		for _, v := range r.Vulnerabilities {
			if v.Severity == "" || v.Applicability != "" {
				continue
			}
			countBySeverity[v.Severity]++
			if hostsBySeverity[v.Severity] == nil {
				hostsBySeverity[v.Severity] = map[string]bool{}
			}
			hostsBySeverity[v.Severity][r.IP] = true
		}
	}

	var summary []SeveritySummaryEntry
	for _, sev := range severityOrder {
		if countBySeverity[sev] == 0 {
			continue
		}
		hosts := make([]string, 0, len(hostsBySeverity[sev]))
		for h := range hostsBySeverity[sev] {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		summary = append(summary, SeveritySummaryEntry{Severity: sev, Count: countBySeverity[sev], Hosts: hosts})
	}
	return summary
}
