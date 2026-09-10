package target

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ParseTarget(target string) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, nil
	}

	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}

	if strings.Contains(target, "-") {
		return expandRange(target)
	}

	if ip := net.ParseIP(target); ip != nil {
		return []string{ip.String()}, nil
	}

	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf("could not resolve target '%s': %w", target, err)
	}

	// Prefer A records when both exist, matching the connect/UDP/service-
	// detection scan paths' existing IPv4-first behavior, but fall back to
	// AAAA (IPv6-only hosts) instead of erroring outright.
	var v4, v6 []string
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			v4 = append(v4, ip4.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}

	if len(v4) > 0 {
		return v4, nil
	}
	if len(v6) > 0 {
		return v6, nil
	}

	return nil, fmt.Errorf("no address found for '%s'", target)
}

func ParseTargets(targets []string) ([]string, error) {
	var allIPs []string
	for _, t := range targets {
		ips, err := ParseTarget(t)
		if err != nil {
			return nil, err
		}
		allIPs = append(allIPs, ips...)
	}
	return allIPs, nil
}

// maxIPv6CIDRHostBits caps how many host bits (and so how many addresses)
// expandCIDR is willing to materialize for an IPv6 prefix. Unlike IPv4's
// 32-bit space, a /64 or wider IPv6 prefix has vastly more addresses than
// any scan -- or this process's memory -- could hold, so anything wider
// than this errors out instead of trying to enumerate 2^(128-n) addresses
// into a slice. 20 host bits caps a single CIDR at ~1M addresses (e.g. a
// /108), already a large scan by IPv4 standards.
const maxIPv6CIDRHostBits = 20

func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR format '%s': %w", cidr, err)
	}

	ones, bits := ipnet.Mask.Size()
	if bits == 128 && bits-ones > maxIPv6CIDRHostBits {
		return nil, fmt.Errorf("IPv6 CIDR '%s' is too large to expand (%d host bits, max %d supported) -- use a narrower prefix", cidr, bits-ones, maxIPv6CIDRHostBits)
	}

	var ips []string

	currIP := make(net.IP, len(ipnet.IP))
	copy(currIP, ipnet.IP)

	for ipnet.Contains(currIP) {
		ips = append(ips, currIP.String())
		incIP(currIP)
	}

	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func expandRange(target string) ([]string, error) {

	if strings.Count(target, "-") == 1 && strings.Count(target, ".") == 6 {
		parts := strings.Split(target, "-")
		startIP := net.ParseIP(parts[0]).To4()
		endIP := net.ParseIP(parts[1]).To4()

		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IP address in range: %s", target)
		}

		var ips []string
		curr := make(net.IP, len(startIP))
		copy(curr, startIP)

		for {
			ips = append(ips, curr.String())
			if curr.String() == endIP.String() {
				break
			}
			incIP(curr)
		}
		return ips, nil
	}

	parts := strings.Split(target, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid range format: %s", target)
	}

	if strings.Contains(parts[3], "-") {
		subParts := strings.Split(parts[3], "-")
		if len(subParts) != 2 {
			return nil, fmt.Errorf("malformed octet range: %s", parts[3])
		}

		start, err1 := strconv.Atoi(subParts[0])
		end, err2 := strconv.Atoi(subParts[1])
		if err1 != nil || err2 != nil || start > end || start < 0 || end > 255 {
			return nil, fmt.Errorf("invalid octet range in %s", target)
		}

		basePrefix := strings.Join(parts[:3], ".")
		var ips []string
		for i := start; i <= end; i++ {
			ips = append(ips, fmt.Sprintf("%s.%d", basePrefix, i))
		}
		return ips, nil
	}

	return nil, fmt.Errorf("unsupported range format: %s", target)
}
