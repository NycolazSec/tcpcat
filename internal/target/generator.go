// internal/target/generator.go
package target

import (
	"fmt"
	"math/rand"
	"net"
	"time"
)

// GenerateRandomIPs génère 'count' adresses IPv4 publiques aléatoires (-iR).
func GenerateRandomIPs(count int) []string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var ips []string

	for len(ips) < count {
		// Génération de 4 octets
		o1 := r.Intn(256)
		o2 := r.Intn(256)
		o3 := r.Intn(256)
		o4 := r.Intn(256)

		// Exclusion des plages privées/réservées (0.x, 10.x, 127.x, 169.254.x, 172.16-31.x, 192.168.x, 224+.x)
		if o1 == 0 || o1 == 10 || o1 == 127 || (o1 == 169 && o2 == 254) ||
			(o1 == 172 && o2 >= 16 && o2 <= 31) || (o1 == 192 && o2 == 168) || o1 >= 224 {
			continue
		}

		ipStr := fmt.Sprintf("%d.%d.%d.%d", o1, o2, o3, o4)
		ips = append(ips, ipStr)
	}

	return ips
}

// FilterExcluded retire les adresses correspondant aux cibles/CIDRs exclues (--exclude).
func FilterExcluded(targets []string, excludeList []string) []string {
	if len(excludeList) == 0 {
		return targets
	}

	// Préparation des masques/IPs à exclure
	var excludedIPs []net.IP
	var excludedNets []*net.IPNet

	for _, ex := range excludeList {
		if _, ipnet, err := net.ParseCIDR(ex); err == nil {
			excludedNets = append(excludedNets, ipnet)
		} else if ip := net.ParseIP(ex); ip != nil {
			excludedIPs = append(excludedIPs, ip)
		}
	}

	var filtered []string
	for _, t := range targets {
		ip := net.ParseIP(t)
		if ip == nil {
			continue
		}

		isExcluded := false

		// Vérification IP exacte
		for _, exIP := range excludedIPs {
			if ip.Equal(exIP) {
				isExcluded = true
				break
			}
		}

		// Vérification appartenance sous-réseau
		if !isExcluded {
			for _, exNet := range excludedNets {
				if exNet.Contains(ip) {
					isExcluded = true
					break
				}
			}
		}

		if !isExcluded {
			filtered = append(filtered, t)
		}
	}

	return filtered
}