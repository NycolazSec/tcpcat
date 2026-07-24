// internal/scan/stealth.go
package scan

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"tcpcat/config"
)

type StealthType int

const (
	ScanNull StealthType = iota
	ScanFin
	ScanXmas
)

// ScanStealthPort exécute un scan NULL, FIN ou Xmas via Raw Sockets.
func ScanStealthPort(targetIP string, port int, scanType StealthType, opts *config.Options, timeout time.Duration) TargetResult {
	res := TargetResult{
		IP:    targetIP,
		Port:  port,
		State: StateOpenFiltered,
	}

	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		res.Reason = "Invalid IPv4 address"
		return res
	}

	// Resolution dynamique de l'IP source
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

	var flags byte
	switch scanType {
	case ScanNull:
		flags = 0x00 // Aucun flag
	case ScanFin:
		flags = 0x01 // FIN
	case ScanXmas:
		flags = 0x29 // FIN (0x01) + PSH (0x08) + URG (0x20)
	}

	// Construction de l'en-tête TCP (20 octets)
	tcpHeader := make([]byte, 20)
	tcpHeader[0] = byte(srcPort >> 8)
	tcpHeader[1] = byte(srcPort)
	tcpHeader[2] = byte(port >> 8)
	tcpHeader[3] = byte(port)
	tcpHeader[4] = 0x00 // Sequence number
	tcpHeader[5] = 0x00
	tcpHeader[6] = 0x00
	tcpHeader[7] = 0x01
	tcpHeader[8] = 0x00 // Ack number
	tcpHeader[9] = 0x00
	tcpHeader[10] = 0x00
	tcpHeader[11] = 0x01
	tcpHeader[12] = 0x50 // Data Offset (20 octets)
	tcpHeader[13] = flags
	tcpHeader[14] = 0xfa // Window Size
	tcpHeader[15] = 0xf0
	tcpHeader[16] = 0x00 // Checksum
	tcpHeader[17] = 0x00
	tcpHeader[18] = 0x00
	tcpHeader[19] = 0x00

	// Calcul du checksum TCP valide
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
			// Selon RFC 793 : Aucune réponse = Port Ouvert ou Filtré
			res.Latency = time.Since(t0)
			res.LatencyMs = float64(res.Latency.Microseconds()) / 1000.0
			res.State = StateOpenFiltered
			res.Reason = "No RST received (RFC 793 Open|Filtered)"
			return res
		}

		if n >= 40 {
			// Gestion de l'offset BSD Loopback sous macOS
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

					// Validation : Le paquet reçu doit correspondre exactement au port scanné
					if srcPortRecv == port && dstPortRecv == srcPort {
						recvFlags := buf[tcpOffset+13]
						res.Latency = time.Since(t0)
						res.LatencyMs = float64(res.Latency.Microseconds()) / 1000.0

						if recvFlags&0x04 != 0 { // Flag RST
							res.State = StateClosed
							res.Reason = "RST Received (Closed)"
							return res
						}
					}
				}
			}
		}
	}
}