// internal/discovery/traceroute.go
package discovery

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

type HopResult struct {
	Hop       int           `json:"hop"`
	IP        string        `json:"ip"`
	Hostname  string        `json:"hostname"`
	Latency   time.Duration `json:"latency"`
	LatencyMs float64       `json:"latency_ms"`
	Reached   bool          `json:"reached"`
}

// RunTraceroute executes a TCP traceroute by varying the IP TTL and intercepting ICMP packets.
func RunTraceroute(targetIP string, port int, maxHops int, timeout time.Duration) []HopResult {
	var hops []HopResult

	for ttl := 1; ttl <= maxHops; ttl++ {
		// ICMP listener in privileged mode (sudo)
		var icmpConn net.PacketConn
		var errICMP error
		if os.Geteuid() == 0 {
			icmpConn, errICMP = net.ListenPacket("ip4:icmp", "0.0.0.0")
			if errICMP == nil {
				_ = icmpConn.SetReadDeadline(time.Now().Add(timeout))
			}
		}

		dialer := &net.Dialer{
			Timeout: timeout,
			Control: func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
				})
			},
		}

		t0 := time.Now()
		conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", targetIP, port))
		latency := time.Since(t0)

		hop := HopResult{
			Hop:       ttl,
			IP:        "*",
			Latency:   latency,
			LatencyMs: float64(latency.Microseconds()) / 1000.0,
		}

		if err == nil {
			conn.Close()
			hop.IP = targetIP
			hop.Reached = true
		} else if strings.Contains(err.Error(), "refused") {
			hop.IP = targetIP
			hop.Reached = true
		} else if icmpConn != nil {
			// Read the ICMP response (Time Exceeded) returned by the router
			buf := make([]byte, 512)
			n, peer, errRead := icmpConn.ReadFrom(buf)
			if errRead == nil && n > 0 {
				hop.IP = peer.String()
				if hop.IP == targetIP {
					hop.Reached = true
				}
			}
		}

		if icmpConn != nil {
			icmpConn.Close()
		}

		if hop.IP != "*" {
			names, _ := net.LookupAddr(hop.IP)
			if len(names) > 0 {
				hop.Hostname = strings.TrimSuffix(names[0], ".")
			}
		}

		hops = append(hops, hop)

		if hop.Reached {
			break
		}
	}

	return hops
}