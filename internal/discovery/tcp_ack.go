// internal/discovery/tcp_ack.go
package discovery

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func PingTCP(ip string, port int, useACK bool, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false // Timeout -> host is down or filtered
		}
		if strings.Contains(err.Error(), "refused") {
			return true // Connection refused -> host is up
		}
		return false // Other errors -> conservatively assume host is down
	}
	defer conn.Close()
	return true
}
