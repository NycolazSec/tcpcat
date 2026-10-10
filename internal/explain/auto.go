package explain

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/NycolazSec/tcpcat/internal/inventory"
)

// Ranges that are never the address the outside world reaches a host on.
var nonPublic = mustCIDRs(
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", // private, CGNAT
	"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7",
)

func mustCIDRs(list ...string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range list {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// IsPublic reports whether ip is a globally routable unicast address.
func IsPublic(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() {
		return false
	}
	for _, n := range nonPublic {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// PublicAddresses lists the host's public addresses, IPv4 first.
func PublicAddresses(inv inventory.Inventory) []string {
	var v4, v6 []string
	for _, a := range inv.Addresses {
		ip := net.ParseIP(a)
		if !IsPublic(ip) {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	return append(v4, v6...)
}

// PortsToProbe is every port worth probing from outside for this host: the
// ones a socket listens on beyond loopback, the ports and node ports of
// externally exposed Kubernetes Services, plus extra. Scanning these few
// instead of all 65535 is faster and far less likely to trip anti-scan
// protections on the path, which otherwise make results flicker.
func PortsToProbe(inv inventory.Inventory, extra []int) []int {
	set := map[int]bool{}
	for _, l := range inv.Listeners {
		if ip := net.ParseIP(l.Address); ip != nil && ip.IsLoopback() {
			continue
		}
		set[l.Port] = true
	}
	for _, s := range inv.Services {
		set[s.Port] = true
		if s.NodePort > 0 {
			set[s.NodePort] = true
		}
	}
	for _, p := range extra {
		set[p] = true
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// ParsePortList reads "22,80,443,25565-25570" (an optional "/tcp" suffix
// is accepted on each entry).
func ParsePortList(spec string) ([]int, error) {
	var out []int
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSuffix(strings.TrimSpace(raw), "/tcp")
		if entry == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(entry, "-")
		start, err := strconv.Atoi(lo)
		end := start
		if err == nil && isRange {
			end, err = strconv.Atoi(hi)
		}
		if err != nil || start < 1 || end > 65535 || end < start {
			return nil, fmt.Errorf("invalid port %q", raw)
		}
		for p := start; p <= end; p++ {
			out = append(out, p)
		}
	}
	return out, nil
}

// CanaryPorts picks n high ports that, according to the inventory, nothing
// listens on and no Kubernetes Service maps, and that are not in avoid. If
// one of them answers as open from outside, something on the path (VPN,
// transparent proxy, antivirus, anti-DDoS SYN proxy) is completing
// handshakes on the host's behalf, and no "open" result can be trusted.
func CanaryPorts(inv inventory.Inventory, avoid []int, n int) []int {
	used := map[int]bool{}
	for _, l := range inv.Listeners {
		used[l.Port] = true
	}
	for _, s := range inv.Services {
		used[s.Port], used[s.NodePort] = true, true
	}
	for _, p := range avoid {
		used[p] = true
	}
	// Spread over the dynamic range; fixed seeds keep runs comparable.
	candidates := []int{47231, 51873, 58419, 49157, 53987, 61243, 45589, 56701}
	var out []int
	for _, p := range candidates {
		if len(out) == n {
			break
		}
		if !used[p] {
			out = append(out, p)
		}
	}
	return out
}
