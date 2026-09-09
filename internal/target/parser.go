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
		if ip4 := ip.To4(); ip4 != nil {
			return []string{ip4.String()}, nil
		}
	}

	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf("could not resolve target '%s': %w", target, err)
	}

	var resolved []string
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			resolved = append(resolved, ip4.String())
		}
	}

	if len(resolved) == 0 {
		return nil, fmt.Errorf("no IPv4 address found for '%s'", target)
	}

	return resolved, nil
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

func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR format '%s': %w", cidr, err)
	}

	var ips []string

	currIP := make(net.IP, len(ipnet.IP))
	copy(currIP, ipnet.IP)

	for ipnet.Contains(currIP) {
		if ip4 := currIP.To4(); ip4 != nil {
			ips = append(ips, ip4.String())
		}
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
