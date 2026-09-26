//go:build !linux

package discovery

import (
	"fmt"
	"time"
)

// ARPScan is Linux-only (it needs an AF_PACKET raw socket). Elsewhere it
// always errors so callers fall back to the regular ping-based path.
func ARPScan(ips []string, ifaceName string, timeout time.Duration) (map[string]bool, error) {
	return nil, fmt.Errorf("native ARP discovery is only supported on Linux")
}
