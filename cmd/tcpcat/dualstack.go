package main

import (
	"context"
	"fmt"
	"net"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/dualstack"
	"github.com/NycolazSec/tcpcat/internal/scan"
)

// runDualStackScan resolves the IPv6 counterparts of the IPv4 targets, scans
// them on the same ports and returns the pairs plus results extended with
// the IPv6 ones. The IPv6 leg always uses TCP connect: the raw-packet scan
// paths only build IPv4 headers.
func runDualStackScan(opts *config.Options, targets []string, names map[string]string, ports []int, results []scan.TargetResult) ([]dualstack.Pair, []scan.TargetResult) {
	fmt.Println(config.Bold + "────────────────────────────────────────────────────────────────────────────────" + config.Reset)
	if opts.UdpScan {
		fmt.Printf("%s[!] --dual-stack compares TCP exposure only; skipped for this UDP scan.%s\n", config.Red, config.Reset)
		return nil, results
	}
	fmt.Printf("%s[*] Dual-stack: looking up the IPv6 address (DNS AAAA) of each IPv4 target...%s\n", config.White, config.Reset)

	pairs := dualstack.FindPairs(context.Background(), targets, names, net.DefaultResolver)
	if len(pairs) == 0 {
		fmt.Printf("%s[*] Dual-stack: no target publishes an IPv6 address; nothing to compare.%s\n", config.Gray, config.Reset)
		return nil, results
	}
	v6Targets := dualstack.IPv6Targets(pairs)
	for _, p := range pairs {
		fmt.Printf("    ├─ %s (%s) ↔ %s\n", p.IPv4, p.Name, p.IPv6)
	}

	// Already-scanned addresses (an IPv6 target given explicitly) are not
	// scanned twice.
	scanned := map[string]bool{}
	for _, r := range results {
		scanned[r.IP] = true
	}
	var toScan []string
	for _, ip := range v6Targets {
		if !scanned[ip] {
			toScan = append(toScan, ip)
		}
	}
	if len(toScan) == 0 {
		return pairs, results
	}

	v6opts := *opts
	v6opts.ConnectScan = true
	v6opts.SynScan, v6opts.AckScan, v6opts.WindowScan = false, false, false
	v6opts.NullScan, v6opts.FinScan, v6opts.XmasScan = false, false, false
	v6opts.ZombieHost, v6opts.DecoyIPs, v6opts.RelayServer = "", "", ""
	v6opts.Resume = "" // the checkpoint belongs to the IPv4 scan
	fmt.Printf("%s[*] Dual-stack: scanning %d IPv6 address(es) on the same %d port(s) (TCP connect)...%s\n",
		config.White, len(toScan), len(ports), config.Reset)
	v6results := scan.NewEngine(&v6opts).Execute(toScan, ports)
	return pairs, append(results, v6results...)
}

// reportDualStackGaps compares each pair's open ports, annotates the IPv6
// results that are exposed on IPv6 only, and prints the differences.
func reportDualStackGaps(pairs []dualstack.Pair, results []scan.TargetResult) {
	var v4, v6 []scan.TargetResult
	v6Index := map[string]bool{}
	for _, p := range pairs {
		v6Index[p.IPv6] = true
	}
	var v6Positions []int
	for i, r := range results {
		if v6Index[r.IP] {
			v6 = append(v6, r)
			v6Positions = append(v6Positions, i)
		} else {
			v4 = append(v4, r)
		}
	}

	gaps := dualstack.Compare(pairs, v4, v6)
	dualstack.Annotate(v6, gaps)
	for k, i := range v6Positions {
		results[i] = v6[k]
	}

	fmt.Println(config.Bold + "────────────────────────────────────────────────────────────────────────────────" + config.Reset)
	if len(gaps) == 0 {
		fmt.Printf("%s[✓] Dual-stack: IPv4 and IPv6 expose the same ports on every compared host.%s\n", config.White, config.Reset)
		return
	}
	ipv6Only := 0
	for _, g := range gaps {
		switch g.Kind {
		case dualstack.GapIPv6Only:
			ipv6Only++
			label := "[!]"
			if g.Sensitive {
				label = "[!!]"
			}
			fmt.Printf("%s%s IPv6-only exposure: %s port %d open on %s, not on %s%s\n",
				config.Red, label, g.Name, g.Port, g.IPv6, g.IPv4, config.Reset)
		case dualstack.GapIPv4Only:
			fmt.Printf("%s[i] IPv4 only: %s port %d open on %s, not on %s%s\n",
				config.Gray, g.Name, g.Port, g.IPv4, g.IPv6, config.Reset)
		}
	}
	if ipv6Only > 0 {
		fmt.Printf("%s[*] Tip: check that every IPv4 firewall / security-group rule has an IPv6 equivalent (ip6tables, nftables inet family, AAAA-facing load balancers).%s\n",
			config.Gray, config.Reset)
	}
}
