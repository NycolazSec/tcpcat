package scan

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"tcpcat/config"
)

type rawTCPPacket struct {
	Flags      byte
	WindowSize uint16
	IPID       uint16
}

type rawTCPScanner struct {
	fd      int
	srcIP   net.IP
	dstIP   net.IP
	srcPort int
	dstPort int
	timeout time.Duration
	t0      time.Time
}

func newRawTCPScanner(targetIP string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP) (*rawTCPScanner, error) {
	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}

	var srcIP net.IP
	if spoofedSrcIP != nil {
		srcIP = spoofedSrcIP.To4()
	} else {
		srcIP = net.ParseIP("127.0.0.1").To4()
		if conn, err := net.Dial("udp", fmt.Sprintf("%s:80", targetIP)); err == nil {
			srcIP = conn.LocalAddr().(*net.UDPAddr).IP.To4()
			conn.Close()
		}
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("raw Socket error (sudo required): %v", err)
	}

	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	srcPort := 54321
	if opts != nil && opts.SourcePort > 0 {
		srcPort = opts.SourcePort
	}

	return &rawTCPScanner{
		fd:      fd,
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: srcPort,
		dstPort: port,
		timeout: timeout,
	}, nil
}

func (s *rawTCPScanner) Send(flags byte) error {
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(s.srcPort))
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(s.dstPort))
	binary.BigEndian.PutUint32(tcpHeader[4:8], 1)
	binary.BigEndian.PutUint32(tcpHeader[8:12], 1)
	tcpHeader[12] = 0x50
	tcpHeader[13] = flags
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)

	cs := calcTCPChecksum(s.srcIP, s.dstIP, tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], cs)

	var destAddr [4]byte
	copy(destAddr[:], s.dstIP)
	sockAddr := &syscall.SockaddrInet4{
		Port: s.dstPort,
		Addr: destAddr,
	}

	s.t0 = time.Now()
	return syscall.Sendto(s.fd, tcpHeader, 0, sockAddr)
}

func (s *rawTCPScanner) Receive() (*rawTCPPacket, error) {
	buf := make([]byte, 1024)
	for {
		n, _, err := syscall.Recvfrom(s.fd, buf, 0)
		if err != nil {
			return nil, err
		}

		if n < 40 {
			continue
		}

		ipOffset := 0
		if n >= 4 && (buf[0]&0xf0 != 0x40) && (buf[4]&0xf0 == 0x40) {
			ipOffset = 4
		}

		if n < ipOffset+20 {
			continue
		}

		ipID := binary.BigEndian.Uint16(buf[ipOffset+4 : ipOffset+6])
		ipHeaderLen := int(buf[ipOffset]&0x0f) * 4
		tcpOffset := ipOffset + ipHeaderLen

		if n < tcpOffset+20 {
			continue
		}

		srcPortRecv := int(binary.BigEndian.Uint16(buf[tcpOffset : tcpOffset+2]))
		dstPortRecv := int(binary.BigEndian.Uint16(buf[tcpOffset+2 : tcpOffset+4]))

		if srcPortRecv == s.dstPort && dstPortRecv == s.srcPort {
			return &rawTCPPacket{
				Flags:      buf[tcpOffset+13],
				WindowSize: binary.BigEndian.Uint16(buf[tcpOffset+14 : tcpOffset+16]),
				IPID:       ipID,
			}, nil
		}
	}
}

func (s *rawTCPScanner) Latency() time.Duration {
	return time.Since(s.t0)
}

func (s *rawTCPScanner) Close() {
	syscall.Close(s.fd)
}

func calcTCPChecksum(srcIP, dstIP net.IP, tcpHeader []byte) uint16 {
	pseudo := make([]byte, 12+len(tcpHeader))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = 6
	tcpLen := uint16(len(tcpHeader))
	binary.BigEndian.PutUint16(pseudo[10:12], tcpLen)
	copy(pseudo[12:], tcpHeader)

	return xdpChecksum(pseudo)
}
