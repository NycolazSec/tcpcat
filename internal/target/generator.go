// internal/target/generator.go
package target

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"
)

type RandomCIDRGenerator struct {
	baseIP   uint32
	m        uint64
	a        uint64
	c        uint64
	currentX uint64
	count    uint64
}

func NewRandomCIDRGenerator(cidr string) (*RandomCIDRGenerator, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR format '%s': %w", cidr, err)
	}

	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 CIDRs are supported")
	}

	m := uint64(1) << (bits - ones)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	c := uint64(r.Int63()) | 1

	var a uint64
	if m < 4 {
		a = 1
	} else {
		k := uint64(r.Int63n(int64(m / 4)))
		a = 4*k + 1
	}

	return &RandomCIDRGenerator{
		baseIP:   binary.BigEndian.Uint32(ipnet.IP.To4()),
		m:        m,
		a:        a,
		c:        c,
		currentX: uint64(r.Int63n(int64(m))),
		count:    0,
	}, nil
}

func (g *RandomCIDRGenerator) NextIP() (string, error) {
	if g.count >= g.m {
		return "", io.EOF
	}

	ipAsUint32 := g.baseIP + uint32(g.currentX)
	ipBytes := make(net.IP, 4)
	binary.BigEndian.PutUint32(ipBytes, ipAsUint32)

	g.currentX = (g.a*g.currentX + g.c) % g.m
	g.count++

	return ipBytes.String(), nil
}

func GenerateRandomIPs(count int) []string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var ips []string

	for len(ips) < count {
		o1 := r.Intn(256)
		o2 := r.Intn(256)
		o3 := r.Intn(256)
		o4 := r.Intn(256)

		if o1 == 0 || o1 == 10 || o1 == 127 || (o1 == 169 && o2 == 254) ||
			(o1 == 172 && o2 >= 16 && o2 <= 31) || (o1 == 192 && o2 == 168) || o1 >= 224 {
			continue
		}

		ipStr := fmt.Sprintf("%d.%d.%d.%d", o1, o2, o3, o4)
		ips = append(ips, ipStr)
	}

	return ips
}

func FilterExcluded(targets []string, excludeList []string) []string {
	if len(excludeList) == 0 {
		return targets
	}

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

		for _, exIP := range excludedIPs {
			if ip.Equal(exIP) {
				isExcluded = true
				break
			}
		}

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
