package discovery

import (
	"net"
	"strconv"
	"strings"
	"time"
)

func PingTCP(ip string, port int, useACK bool, timeout time.Duration) bool {
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false
		}
		if strings.Contains(err.Error(), "refused") {
			return true
		}
		return false
	}
	defer func() { _ = conn.Close() }()
	return true
}
