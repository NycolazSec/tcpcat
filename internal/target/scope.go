package target

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func FilterByScope(targetIPs []string, scopeFile string) ([]string, error) {
	file, err := os.Open(scopeFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open scope file %q: %w", scopeFile, err)
	}
	defer func() { _ = file.Close() }()

	allowedIPs := make(map[string]struct{})
	var allowedNetworks []*net.IPNet
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entry := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			allowedNetworks = append(allowedNetworks, network)
			continue
		}
		ips, err := ParseTarget(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid scope entry %q: %w", entry, err)
		}
		for _, ip := range ips {
			allowedIPs[ip] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read scope file: %w", err)
	}
	if len(allowedIPs) == 0 && len(allowedNetworks) == 0 {
		return nil, fmt.Errorf("scope file contains no valid entries")
	}

	var scoped []string
	for _, targetIP := range targetIPs {
		if _, allowed := allowedIPs[targetIP]; allowed {
			scoped = append(scoped, targetIP)
			continue
		}
		parsedIP := net.ParseIP(targetIP)
		for _, network := range allowedNetworks {
			if network.Contains(parsedIP) {
				scoped = append(scoped, targetIP)
				break
			}
		}
	}
	return scoped, nil
}
