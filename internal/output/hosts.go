package output

import "tcpcat/internal/scan"

// hostResults is one scanned host and everything found on it.
type hostResults struct {
	IP      string
	Results []scan.TargetResult
}

// groupByIP splits a flat result list into per-host groups. Every
// file-export format needs this: a scan over a CIDR or an -iL list returns
// one flat slice covering every host, and a format that ignores
// TargetResult.IP (as these all used to) attributes every host's ports to
// a single address -- silently wrong the moment more than one host is up.
//
// Host order follows first appearance rather than map order, and each
// host keeps its own result order, so an export reads the way the scan
// ran and two runs over the same targets diff cleanly.
//
// `target` is the fallback address for results carrying no IP of their
// own, which is what a single-target scan produces.
func groupByIP(target string, results []scan.TargetResult) []hostResults {
	var hosts []hostResults
	indexByIP := make(map[string]int)

	for _, r := range results {
		ip := r.IP
		if ip == "" {
			ip = target
		}
		idx, seen := indexByIP[ip]
		if !seen {
			hosts = append(hosts, hostResults{IP: ip})
			idx = len(hosts) - 1
			indexByIP[ip] = idx
		}
		hosts[idx].Results = append(hosts[idx].Results, r)
	}

	return hosts
}
