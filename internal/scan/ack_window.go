// internal/scan/ack_window.go
package scan

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"tcpcat/config"
)

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func calcTCPChecksum(srcIP, dstIP net.IP, tcpHeader []byte) uint16 {
	pseudo := make([]byte, 12+len(tcpHeader))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = 6 // IPPROTO_TCP
	tcpLen := uint16(len(tcpHeader))
	pseudo[10] = byte(tcpLen >> 8)
	pseudo[11] = byte(tcpLen)
	copy(pseudo[12:], tcpHeader)
	return checksum(pseudo)
}

// ScanAckPort réalise un ACK Scan (-sA) pour cartographier le filtrage du pare-feu.
func ScanAckPort(targetIP string, port int, opts *config.Options, timeout time.Duration) TargetResult {
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

	// Détermination dynamique de l'IP source
	srcIP := net.ParseIP("127.0.0.1").To4()
	if conn, err := net.Dial("udp", fmt.Sprintf("%s:80", targetIP)); err == nil {
		srcIP = conn.LocalAddr().(*net.UDPAddr).IP.To4()
		conn.Close()
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
	tcpHeader[8] = 0x00
	tcpHeader[9] = 0x00
	tcpHeader[10] = 0x00
	tcpHeader[11] = 0x01
	tcpHeader[12] = 0x50 // Data Offset (20 octets)
	tcpHeader[13] = 0x10 // Flag ACK
	tcpHeader[14] = 0xfa
	tcpHeader[15] = 0xf0

	cs := calcTCPChecksum(srcIP, dstIP, tcpHeader)
	tcpHeader[16] = byte(cs >> 8)
	tcpHeader[17] = byte(cs)

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
			res.Reason = "No response (Stateful Firewall)"
			return res
		}

		if n >= 40 {
			ipOffset := 0
			if n >= 4 && (buf[0]&0xf0 != 0x40) && (buf[4]&0xf0 == 0x40) {
				ipOffset = 4
			}

			if n >= ipOffset+20 {
				ipHeaderLen := int(buf[ipOffset]&0x0f) * 4
				tcpOffset := ipOffset + ipHeaderLen

				if n >= tcpOffset+20 {
					srcPortRecv := int(buf[tcpOffset])<<8 | int(buf[tcpOffset+1])
					dstPortRecv := int(buf[tcpOffset+2])<<8 | int(buf[tcpOffset+3])

					if srcPortRecv == port && dstPortRecv == srcPort {
						flags := buf[tcpOffset+13]
						res.Latency = time.Since(t0)
						res.LatencyMs = float64(res.Latency.Microseconds()) / 1000.0

						if flags&0x04 != 0 { // RST
							res.State = StateUnfiltered
							res.Reason = "RST Received (Unfiltered)"
							return res
						}
					}
				}
			}
		}
	}
}

// ScanWindowPort réalise un Window Scan (-sW).
func ScanWindowPort(targetIP string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	res := ScanAckPort(targetIP, port, opts, timeout)
	if res.State == StateUnfiltered {
		res.Reason = "Window Size analyzed (RST Received)"
	}
	return res
}