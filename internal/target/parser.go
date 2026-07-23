// internal/target/parser.go
package target

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseTarget convertit une chaîne cible unique (IP, FQDN, CIDR, plage) en liste d'adresses IPv4.
func ParseTarget(target string) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, nil
	}

	// 1. Notation CIDR (ex: 192.168.1.0/24)
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}

	// 2. Plage d'IP avec tiret (ex: 192.168.1.1-50 ou 192.168.1.1-192.168.1.50)
	if strings.Contains(target, "-") {
		return expandRange(target)
	}

	// 3. Adresse IP IPv4 unique
	if ip := net.ParseIP(target); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return []string{ip4.String()}, nil
		}
	}

	// 4. Résolution DNS (ex: scanme.nmap.org)
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf("impossible de résoudre la cible '%s': %w", target, err)
	}

	var resolved []string
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			resolved = append(resolved, ip4.String())
		}
	}

	if len(resolved) == 0 {
		return nil, fmt.Errorf("aucune adresse IPv4 trouvée pour '%s'", target)
	}

	return resolved, nil
}

// ParseTargets prend une liste de cibles et retourne l'ensemble des adresses IPv4 résolues.
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

// expandCIDR génère toutes les IP utilisables d'un sous-réseau CIDR.
func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("format CIDR invalide '%s': %w", cidr, err)
	}

	var ips []string
	// Copie propre pour éviter les problèmes de référence mémoire lors de l'incrémentation
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

// incIP incrémente une adresse IP byte par byte.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// expandRange prend en charge les formats 192.168.1.1-50 et 192.168.1.1-192.168.1.50.
func expandRange(target string) ([]string, error) {
	// Cas 1 : Plage complète d'IP (ex: 192.168.1.1-192.168.1.50)
	if strings.Count(target, "-") == 1 && strings.Count(target, ".") == 6 {
		parts := strings.Split(target, "-")
		startIP := net.ParseIP(parts[0]).To4()
		endIP := net.ParseIP(parts[1]).To4()

		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("adresse IP invalide dans la plage: %s", target)
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

	// Cas 2 : Plage sur le dernier octet (ex: 192.168.1.1-50)
	parts := strings.Split(target, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("format de plage invalide: %s", target)
	}

	if strings.Contains(parts[3], "-") {
		subParts := strings.Split(parts[3], "-")
		if len(subParts) != 2 {
			return nil, fmt.Errorf("plage d'octets malformée: %s", parts[3])
		}

		start, err1 := strconv.Atoi(subParts[0])
		end, err2 := strconv.Atoi(subParts[1])
		if err1 != nil || err2 != nil || start > end || start < 0 || end > 255 {
			return nil, fmt.Errorf("plage d'octets invalide dans %s", target)
		}

		basePrefix := strings.Join(parts[:3], ".")
		var ips []string
		for i := start; i <= end; i++ {
			ips = append(ips, fmt.Sprintf("%s.%d", basePrefix, i))
		}
		return ips, nil
	}

	return nil, fmt.Errorf("format de plage non supporté: %s", target)
}