// internal/discovery/dns.go
package discovery

import (
	"context"
	"net"
	"strings"
	"time"
)

// ResolveCustomDNS permet de résoudre un hôte via des serveurs DNS personnalisés.
func ResolveCustomDNS(host string, dnsServers []string) ([]string, error) {
	if len(dnsServers) == 0 {
		return net.LookupHost(host)
	}

	server := dnsServers[0]
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", server)
		},
	}

	return resolver.LookupHost(context.Background(), host)
}