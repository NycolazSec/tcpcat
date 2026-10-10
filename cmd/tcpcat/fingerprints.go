package main

import (
	"fmt"
	"strings"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/fingerprint"
	"github.com/NycolazSec/tcpcat/internal/scan"
)

// reportUnknownServices groups the services -sV could not name. A group seen
// on several hosts is worth a signature, so those are printed with one;
// one-off unknowns are only counted.
func reportUnknownServices(opts *config.Options, results []scan.TargetResult) {
	clusters := fingerprint.Group(results)
	if len(clusters) == 0 {
		return
	}
	fmt.Println(config.Bold + "────────────────────────────────────────────────────────────────────────────────" + config.Reset)
	singles := 0
	for _, c := range clusters {
		if c.Hosts < 2 {
			singles++
			continue
		}
		var eps []string
		for i, ep := range c.Endpoints {
			if i == 5 {
				eps = append(eps, fmt.Sprintf("+%d more", len(c.Endpoints)-5))
				break
			}
			eps = append(eps, hostPort(ep.IP, ep.Port))
		}
		fmt.Printf("%s[?] Same unrecognized service on %d hosts [%s]: %q%s\n", config.White, c.Hosts, c.ID, c.Template, config.Reset)
		fmt.Printf("    %s%s%s\n", config.Gray, strings.Join(eps, ", "), config.Reset)
		fmt.Printf("    %ssuggested signature: %s%s\n", config.Gray, c.Suggested, config.Reset)
	}
	if singles > 0 {
		fmt.Printf("%s[?] %d other unrecognized service(s) seen on a single host.%s\n", config.Gray, singles, config.Reset)
	}
	if opts.FingerprintOut != "" {
		if err := fingerprint.Export(opts.FingerprintOut, clusters); err != nil {
			fmt.Printf("%s[!] Failed to export fingerprints: %v%s\n", config.Red, err, config.Reset)
		} else {
			fmt.Printf("%s[✓] %d unknown-service template(s) exported to %s (no addresses, no raw banners).%s\n",
				config.White, len(clusters), opts.FingerprintOut, config.Reset)
		}
	}
}
