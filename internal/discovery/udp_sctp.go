// internal/discovery/udp_sctp.go
package discovery

import (
	"fmt"
	"net"
	"time"
)

// PingUDP sends a UDP probe to the specified port (-PU).
// If the host responds or sends an ICMP rejection (Port Unreachable), the host is considered active.
func PingUDP(ip string, port int, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// 1. Send a UDP probe byte
	probeData := []byte{0x00}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	_, err = conn.Write(probeData)
	if err != nil {
		return false
	}

	// 2. Read the potential response
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)

	if err != nil {
		// In case of a timeout, the UDP result remains undetermined
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false
		}
		// Any other error (e.g., connection refused / ICMP port unreachable) confirms that the host is alive
		return true
	}

	// Explicit response received
	return true
}

// PingSCTP attempts a host discovery probe via the SCTP stack (-PY).
func PingSCTP(ip string, port int, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%d", ip, port)

	// Attempt to initialize via the system's protocol driver
	conn, err := net.DialTimeout("sctp", target, timeout)
	if err != nil {
		// An active refusal error also signals the host's presence
		if netErr, ok := err.(net.Error); ok && !netErr.Timeout() {
			return true
		}
		return false
	}

	_ = conn.Close()
	return true
}