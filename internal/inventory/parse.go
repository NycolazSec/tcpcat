package inventory

import (
	"strconv"
	"strings"
)

// PublishedHostPorts reads the host ports out of `docker ps`'s Ports column,
// e.g. "0.0.0.0:5000->5000/tcp, :::5000->5000/tcp, 3306/tcp" -> [5000].
// Unpublished ports (no "->") are skipped.
func PublishedHostPorts(ports string) []int {
	var out []int
	seen := map[int]bool{}
	for _, entry := range strings.Split(ports, ",") {
		hostSide, _, ok := strings.Cut(strings.TrimSpace(entry), "->")
		if !ok {
			continue
		}
		i := strings.LastIndex(hostSide, ":")
		if i < 0 {
			continue
		}
		// A range ("8000-8010") publishes each port of it.
		lo, hi, isRange := strings.Cut(hostSide[i+1:], "-")
		start, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		end := start
		if isRange {
			if end, err = strconv.Atoi(hi); err != nil || end < start || end-start > 1024 {
				continue
			}
		}
		for p := start; p <= end; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// ParseKubeServices reads the kubectl jsonpath output of enrichKubernetes:
// "ns/name<TAB>type<TAB>port:nodePort,port:nodePort,". Only Services that
// can be reached from outside the cluster (NodePort, LoadBalancer) are kept.
func ParseKubeServices(out string) []KubeService {
	var svcs []KubeService
	for _, line := range strings.Split(out, "\n") {
		cols := strings.Split(line, "\t")
		if len(cols) != 3 || (cols[1] != "NodePort" && cols[1] != "LoadBalancer") {
			continue
		}
		for _, pair := range strings.Split(cols[2], ",") {
			portStr, nodeStr, _ := strings.Cut(pair, ":")
			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}
			node, _ := strconv.Atoi(nodeStr)
			svcs = append(svcs, KubeService{Name: cols[0], Type: cols[1], Port: port, NodePort: node})
		}
	}
	return svcs
}
