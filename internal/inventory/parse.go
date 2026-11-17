package inventory

import (
	"encoding/json"
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

// KubePod is a pod as enrichKubernetes reads it from kubectl.
type KubePod struct {
	Name   string // namespace/name
	Labels map[string]string
}

// ParseKubePods reads the kubectl jsonpath output of enrichKubernetes, one
// "uid<TAB>ns/name<TAB>labels" line per pod, labels being the JSON object
// kubectl prints for .metadata.labels (nothing when the pod has none). The
// result is keyed by pod UID. Labels that do not parse as JSON (kubectl
// releases that print Go's map[k:v] form) are dropped and the name is kept:
// remediate then writes a placeholder selector instead of a guessed one.
func ParseKubePods(out string) map[string]KubePod {
	pods := map[string]KubePod{}
	for _, line := range strings.Split(out, "\n") {
		cols := strings.SplitN(line, "\t", 3)
		if len(cols) < 2 || cols[0] == "" {
			continue
		}
		p := KubePod{Name: cols[1]}
		if len(cols) == 3 {
			var labels map[string]string
			if json.Unmarshal([]byte(strings.TrimSpace(cols[2])), &labels) == nil && len(labels) > 0 {
				p.Labels = labels
			}
		}
		pods[cols[0]] = p
	}
	return pods
}
