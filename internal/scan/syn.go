// internal/scan/syn.go
package scan

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"tcpcat/config"
)

// ScanSYNPort exécute un scan TCP SYN (Half-Open) via Raw Sockets.
func ScanSYNPort(targetIP string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	res := TargetResult{
		IP:    targetIP,
		Port:  port,
		State: StateFiltered,
	}

	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		res.Reason = "Invalid IPv4 address"
		return res
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		res.Reason = fmt.Sprintf("Raw Socket error (sudo required): %v", err)
		return res
	}
	defer syscall.Close(fd)

	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	srcPort := 54321
	if opts != nil && opts.SourcePort > 0 {
		srcPort = opts.SourcePort
	}

	tcpHeader := make([]byte, 20)
	tcpHeader[0] = byte(srcPort >> 8)
	tcpHeader[1] = byte(srcPort)
	tcpHeader[2] = byte(port >> 8)
	tcpHeader[3] = byte(port)
	tcpHeader[4] = 0x00
	tcpHeader[5] = 0x00
	tcpHeader[6] = 0x00
	tcpHeader[7] = 0x01
	tcpHeader[12] = 0x50
	tcpHeader[13] = 0x02 // Flag SYN
	tcpHeader[14] = 0xfa
	tcpHeader[15] = 0xf0

	var destAddr [4]byte
	copy(destAddr[:], dstIP)
	sockAddr := &syscall.SockaddrInet4{
		Port: port,
		Addr: destAddr,
	}

	t0 := time.Now()
	err = syscall.Sendto(fd, tcpHeader, 0, sockAddr)
	if err != nil {
		res.Reason = fmt.Sprintf("Send failed: %v", err)
		return res
	}

	buf := make([]byte, 1024)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			res.Latency = time.Since(t0)
			res.LatencyMs = float64(res.Latency.Microseconds()) / 1000.0
			res.State = StateFiltered
			res.Reason = "No response / Timeout"
			return res
		}

		if n >= 40 {
			flags := buf[33]
			if flags&0x12 == 0x12 { // SYN-ACK
				res.Latency = time.Since(t0)
				res.LatencyMs = float64(res.Latency.Microseconds()) / 1000.0
				res.State = StateOpen
				res.Reason = "SYN-ACK Received"
				return res
			} else if flags&0x04 != 0 { // RST
				res.Latency = time.Since(t0)
				res.LatencyMs = float64(res.Latency.Microseconds()) / 1000.0
				res.State = StateClosed
				res.Reason = "RST Received"
				return res
			}
		}
	}
}