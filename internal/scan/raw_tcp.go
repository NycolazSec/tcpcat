//go:build !windows
// +build !windows

package scan

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
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
	relayIP net.IP
	t0      time.Time

	rxKey  string
	rxChan chan *rawTCPPacket
}

// Shared raw-socket receive path -----------------------------------------
//
// Every rawTCPScanner used to open its own raw socket and read replies
// directly off it in Receive(). A raw socket isn't connection-filtered by
// the kernel -- it receives a copy of every matching-protocol packet on
// the interface, not just replies to that one probe -- so with N
// concurrent scan workers, N raw sockets were each independently reading
// and filtering the *same* system-wide traffic. That cost scales with the
// number of concurrent workers regardless of the target's actual network
// latency, which is why a raw-socket scan's wall time stayed almost
// perfectly constant across repeated runs even against a target whose real
// RTT visibly varied.
//
// rawRxLoop now reads from a single shared raw socket once per process and
// demultiplexes replies to whichever rawTCPScanner is waiting for them via
// rawRxWaiters, mirroring the AF_XDP engine's xdpRxLoop/xdpResults pattern.
// Sending is unaffected -- each scanner still owns its own send-only fd,
// since egress was never the bottleneck.
var (
	rawRxOnce    sync.Once
	rawRxErr     error
	rawRxWaiters sync.Map // rawRxKey(...) -> chan *rawTCPPacket
)

// rawRxKey identifies one pending probe: the target host, the port being
// probed (their source port in any reply), and our own source port (their
// destination port in any reply). All three matter -- port numbers alone
// aren't enough once multiple targets are being probed concurrently on the
// same port, which the single-socket-per-job code never actually guarded
// against either (any raw socket would accept a same-port reply from any
// host, not just the one it happened to be probing).
func rawRxKey(remoteIP net.IP, remotePort, localPort int) string {
	return remoteIP.String() + "|" + strconv.Itoa(remotePort) + "|" + strconv.Itoa(localPort)
}

func ensureRawRxLoop() error {
	rawRxOnce.Do(func() {
		// IPPROTO_TCP, not IPPROTO_RAW: on Linux, a SOCK_RAW socket opened
		// with protocol IPPROTO_RAW is send-only (it implies IP_HDRINCL for
		// crafting arbitrary headers, but the kernel gives it no receive
		// queue at all -- see raw(7)). The per-job send path below still
		// uses IPPROTO_RAW deliberately, since sending is unaffected; only
		// the shared *receive* socket needs the actual protocol number
		// (TCP) to have the kernel deliver a copy of matching segments.
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
		if err != nil {
			rawRxErr = fmt.Errorf("raw receive socket error (sudo required): %w", err)
			return
		}
		go rawRxLoop(fd)
	})
	return rawRxErr
}

func rawRxLoop(fd int) {
	buf := make([]byte, 1024)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
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

		srcIP := net.IP(append([]byte(nil), buf[ipOffset+12:ipOffset+16]...))
		srcPortRecv := int(binary.BigEndian.Uint16(buf[tcpOffset : tcpOffset+2]))
		dstPortRecv := int(binary.BigEndian.Uint16(buf[tcpOffset+2 : tcpOffset+4]))

		chAny, ok := rawRxWaiters.Load(rawRxKey(srcIP, srcPortRecv, dstPortRecv))
		if !ok {
			continue
		}
		ch, ok := chAny.(chan *rawTCPPacket)
		if !ok {
			continue
		}

		pkt := &rawTCPPacket{
			Flags:      buf[tcpOffset+13],
			WindowSize: binary.BigEndian.Uint16(buf[tcpOffset+14 : tcpOffset+16]),
			IPID:       ipID,
		}
		select {
		case ch <- pkt:
		default:
			// Waiter already matched (or gave up) -- never block the shared loop.
		}
	}
}

func newRawTCPScanner(targetIP string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP) (*rawTCPScanner, error) {
	parsed := net.ParseIP(targetIP)
	dstIP := parsed.To4()
	if dstIP == nil {
		if parsed != nil {
			return nil, fmt.Errorf("raw-socket scans (SYN/ACK/Window/NULL/FIN/Xmas) only support IPv4; use -sT or -sU for an IPv6 target")
		}
		return nil, fmt.Errorf("invalid IP address: %q", targetIP)
	}

	if err := ensureRawRxLoop(); err != nil {
		return nil, err
	}

	srcIP := getLocalIPv4()
	if spoofedSrcIP != nil {
		srcIP = spoofedSrcIP.To4()
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("raw Socket error (sudo required): %v", err)
	}

	srcPort := 54321
	if opts != nil && opts.SourcePort > 0 {
		srcPort = opts.SourcePort
	}

	// Registered here, before Send() is ever called, not lazily inside
	// Receive(): a fast reply (same-host/LAN RTTs can be sub-millisecond)
	// can otherwise arrive and be processed by rawRxLoop in the window
	// between Send() returning and Receive() getting around to
	// registering its waiter, and rawRxLoop drops anything with no
	// registered waiter -- silently losing a real reply to a race, not a
	// timeout.
	key := rawRxKey(dstIP, port, srcPort)
	ch := make(chan *rawTCPPacket, 1)
	rawRxWaiters.Store(key, ch)

	return &rawTCPScanner{
		fd:      fd,
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: srcPort,
		dstPort: port,
		timeout: timeout,
		relayIP: net.ParseIP(opts.RelayServer),
		rxKey:   key,
		rxChan:  ch,
	}, nil
}

func (s *rawTCPScanner) Send(flags byte) error {
	// Drain a stale reply left over from an earlier retry attempt on this
	// same scanner, so the Receive() that follows can't return it instead
	// of a genuine reply to *this* attempt.
	select {
	case <-s.rxChan:
	default:
	}

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

	var packetToSend []byte
	var destAddr [4]byte

	if s.relayIP != nil {

		innerIPHeader := constructIPv4Header(s.srcIP, s.dstIP, syscall.IPPROTO_TCP, uint16(len(tcpHeader)))
		innerPacket := append(innerIPHeader, tcpHeader...)
		outerIPHeader := constructIPv4Header(getLocalIPv4(), s.relayIP, syscall.IPPROTO_IPIP, uint16(len(innerPacket)))
		packetToSend = append(outerIPHeader, innerPacket...)
		copy(destAddr[:], s.relayIP.To4())
	} else {
		packetToSend = append(constructIPv4Header(s.srcIP, s.dstIP, syscall.IPPROTO_TCP, uint16(len(tcpHeader))), tcpHeader...)
		copy(destAddr[:], s.dstIP.To4())
	}

	sockAddr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: destAddr,
	}

	s.t0 = time.Now()
	return syscall.Sendto(s.fd, packetToSend, 0, sockAddr)
}

func constructIPv4Header(srcIP, dstIP net.IP, protocol byte, payloadLen uint16) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	header[1] = 0x00
	binary.BigEndian.PutUint16(header[2:4], 20+payloadLen)
	binary.BigEndian.PutUint16(header[4:6], 0x0000)
	binary.BigEndian.PutUint16(header[6:8], 0x4000)
	header[8] = 64
	header[9] = protocol
	binary.BigEndian.PutUint16(header[10:12], 0x0000)
	copy(header[12:16], srcIP.To4())
	copy(header[16:20], dstIP.To4())

	checksum := calcIPChecksum(header)
	binary.BigEndian.PutUint16(header[10:12], checksum)

	return header
}

func calcIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func (s *rawTCPScanner) Receive() (*rawTCPPacket, error) {
	select {
	case pkt := <-s.rxChan:
		return pkt, nil
	case <-time.After(s.timeout):
		return nil, fmt.Errorf("timeout waiting for response")
	}
}

func (s *rawTCPScanner) Latency() time.Duration {
	return time.Since(s.t0)
}

func (s *rawTCPScanner) Close() {
	rawRxWaiters.Delete(s.rxKey)
	_ = syscall.Close(s.fd)
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
