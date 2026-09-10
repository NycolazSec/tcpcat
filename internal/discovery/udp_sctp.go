package discovery

import (
	"net"
	"strconv"
	"time"
)

func PingUDP(ip string, port int, timeout time.Duration) bool {
	target := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	probeData := []byte{0x00}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	_, err = conn.Write(probeData)
	if err != nil {
		return false
	}

	buf := make([]byte, 1024)
	_, err = conn.Read(buf)

	if err != nil {

		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false
		}

		return true
	}

	return true
}

func PingSCTP(ip string, port int, timeout time.Duration) bool {
	target := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("sctp", target, timeout)
	if err != nil {

		if netErr, ok := err.(net.Error); ok && !netErr.Timeout() {
			return true
		}
		return false
	}

	_ = conn.Close()
	return true
}
