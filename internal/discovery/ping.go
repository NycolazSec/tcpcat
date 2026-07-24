// internal/discovery/ping.go
package discovery

import (
	"fmt"
	"net"
	"time"
)

// PingHost tests if an IP is active by attempting fast TCP connections
// on common admin/web ports (80, 443, 22, 445).
func PingHost(ip string, timeout time.Duration) bool {
	probePorts := []int{80, 443, 22, 445}

	for _, port := range probePorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}