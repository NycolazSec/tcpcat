// Package dualstack finds services exposed on one IP family but not the
// other.
//
// A host published under a name with both A and AAAA records is often
// firewalled for IPv4 only: the rules were written for IPv4 and nobody
// wrote the ip6tables / security-group equivalent, so SSH or a database
// is filtered on 192.0.2.10 yet open on 2001:db8::10. A scan that, like
// tcpcat by default, resolves names to their IPv4 address never sees it.
// --dual-stack resolves each target's IPv6 counterpart through DNS, scans
// it on the same ports, and reports the differences.
package dualstack

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/NycolazSec/tcpcat/internal/scan"
)

// Pair links an IPv4 target to an IPv6 address published for the same name.
type Pair struct {
	Name string `json:"name"`
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

// Resolver is the subset of *net.Resolver used here (stubbed in tests).
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// FindPairs looks up the IPv6 counterparts of IPv4 targets. The name used
// is the one the target was given as (names, from target parsing) or, for a
// bare IP, its reverse-DNS name. Only DNS is consulted: an address nobody
// published under the host's name is out of scope for this check.
func FindPairs(ctx context.Context, ipv4Targets []string, names map[string]string, r Resolver) []Pair {
	var pairs []Pair
	seen := map[string]bool{}
	for _, ip := range ipv4Targets {
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil {
			continue
		}
		name := names[ip]
		if name == "" {
			lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			ptrs, err := r.LookupAddr(lookupCtx, ip)
			cancel()
			if err != nil || len(ptrs) == 0 {
				continue
			}
			name = strings.TrimSuffix(ptrs[0], ".")
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		addrs, err := r.LookupIP(lookupCtx, "ip6", name)
		cancel()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.To4() != nil {
				continue
			}
			key := ip + "|" + a.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			pairs = append(pairs, Pair{Name: name, IPv4: ip, IPv6: a.String()})
		}
	}
	return pairs
}

// IPv6Targets returns the distinct IPv6 addresses to scan.
func IPv6Targets(pairs []Pair) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range pairs {
		if !seen[p.IPv6] {
			seen[p.IPv6] = true
			out = append(out, p.IPv6)
		}
	}
	sort.Strings(out)
	return out
}

const (
	GapIPv6Only = "ipv6-only"
	GapIPv4Only = "ipv4-only"
)

// Gap is a port open on one family's address and not on the other's.
type Gap struct {
	Pair
	Port      int    `json:"port"`
	Kind      string `json:"kind"`
	Sensitive bool   `json:"sensitive"`
}

// sensitivePorts are services that should essentially never be reachable
// by surprise: remote administration, databases, caches, file sharing.
var sensitivePorts = map[int]bool{
	21: true, 22: true, 23: true, 135: true, 139: true, 445: true, 1433: true,
	1521: true, 2375: true, 2379: true, 3306: true, 3389: true, 5432: true,
	5900: true, 5984: true, 6379: true, 8086: true, 9200: true, 10250: true,
	11211: true, 27017: true,
}

// IsSensitive reports whether port belongs to sensitivePorts.
func IsSensitive(port int) bool { return sensitivePorts[port] }

// Compare lists, for every pair, the ports open on one side only. Both
// result sets must cover the same ports for the comparison to mean anything,
// which the caller guarantees by scanning the IPv6 side with the IPv4 port list.
func Compare(pairs []Pair, v4, v6 []scan.TargetResult) []Gap {
	open := map[string]map[int]bool{}
	for _, list := range [][]scan.TargetResult{v4, v6} {
		for _, r := range list {
			if r.State != scan.StateOpen {
				continue
			}
			if open[r.IP] == nil {
				open[r.IP] = map[int]bool{}
			}
			open[r.IP][r.Port] = true
		}
	}

	var gaps []Gap
	for _, p := range pairs {
		for port := range open[p.IPv6] {
			if !open[p.IPv4][port] {
				gaps = append(gaps, Gap{Pair: p, Port: port, Kind: GapIPv6Only, Sensitive: sensitivePorts[port]})
			}
		}
		for port := range open[p.IPv4] {
			if !open[p.IPv6][port] {
				gaps = append(gaps, Gap{Pair: p, Port: port, Kind: GapIPv4Only, Sensitive: sensitivePorts[port]})
			}
		}
	}
	sort.Slice(gaps, func(i, j int) bool {
		a, b := gaps[i], gaps[j]
		if a.Kind != b.Kind {
			return a.Kind > b.Kind // ipv6-only (the risky one) first
		}
		if a.IPv4 != b.IPv4 {
			return a.IPv4 < b.IPv4
		}
		if a.IPv6 != b.IPv6 {
			return a.IPv6 < b.IPv6
		}
		return a.Port < b.Port
	})
	return gaps
}

// Annotate marks the IPv6 results behind each IPv6-only gap so exports
// (JSON, SARIF) carry it, and returns how many results it touched.
func Annotate(v6 []scan.TargetResult, gaps []Gap) int {
	byEndpoint := map[string]Gap{}
	for _, g := range gaps {
		if g.Kind == GapIPv6Only {
			byEndpoint[fmt.Sprintf("%s|%d", g.IPv6, g.Port)] = g
		}
	}
	touched := 0
	for i := range v6 {
		g, ok := byEndpoint[fmt.Sprintf("%s|%d", v6[i].IP, v6[i].Port)]
		if !ok {
			continue
		}
		v6[i].DualStack = &scan.DualStackInfo{Gap: g.Kind, Name: g.Name, Counterpart: g.IPv4, Sensitive: g.Sensitive}
		v6[i].Findings = append(v6[i].Findings, fmt.Sprintf(
			"IPv6-only exposure: port %d is open on %s but not on its IPv4 address %s (%s) -- the IPv4 firewall rules likely have no IPv6 equivalent",
			g.Port, g.IPv6, g.IPv4, g.Name))
		severity := "medium"
		if g.Sensitive {
			severity = "high"
		}
		if severityRank(severity) > severityRank(v6[i].RiskSeverity) {
			v6[i].RiskSeverity = severity
		}
		touched++
	}
	return touched
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
