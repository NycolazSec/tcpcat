//go:build !linux

package discovery

import (
	"fmt"
	"net"
	"time"
)

// ARPScan is Linux-only (it needs an AF_PACKET raw socket). Elsewhere it
// always errors so callers fall back to the regular ping-based path.
func ARPScan(ips []string, ifaceName string, timeout time.Duration) (map[string]bool, error) {
	return nil, fmt.Errorf("native ARP discovery is only supported on Linux")
}

// ARPResolve is Linux-only, like ARPScan.
func ARPResolve(ips []string, ifaceName string, timeout time.Duration) (map[string]net.HardwareAddr, error) {
	return nil, fmt.Errorf("native ARP resolution is only supported on Linux")
}
