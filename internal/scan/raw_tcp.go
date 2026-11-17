//go:build !windows
// +build !windows

package scan

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/netiface"
)

type rawTCPPacket struct {
	Flags      byte
	WindowSize uint16
	IPID       uint16

	// Frame is a copy of the reply as received, with the offsets at which
	// its IP and TCP headers start. OS fingerprinting needs the whole
	// thing -- initial TTL, window, and the negotiated TCP options -- not
	// just the few fields parsed out above, and the shared receive buffer
	// is overwritten by the next packet, so this has to be a copy.
	Frame    []byte
	IPStart  int
	TCPStart int
}

type rawTCPScanner struct {
	fd      int
	srcIP   net.IP
	dstIP   net.IP
	srcPort int
	dstPort int
	timeout time.Duration
	relayIP net.IP
	mptcp   bool // advertise MP_CAPABLE (kind 30) in the SYN, for MPTCP detection
	t0      time.Time
	sa      syscall.SockaddrInet4 // Send's destination, reused across attempts

	rxKey  rawRxKeyT
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
	rawRxWaiters sync.Map // rawRxKeyT -> chan *rawTCPPacket
)

// rawRxKeyT is a comparable value, not a string: the receive loop builds
// one for every TCP segment it reads, and formatting the address into a
// string allocated on each of them.
type rawRxKeyT struct {
	ip                    [4]byte
	remotePort, localPort uint16
}

// rawRxKey identifies one pending probe: the target host, the port being
// probed (their source port in any reply), and our own source port (their
// destination port in any reply). All three matter -- port numbers alone
// aren't enough once multiple targets are being probed concurrently on the
// same port, which the single-socket-per-job code never actually guarded
// against either (any raw socket would accept a same-port reply from any
// host, not just the one it happened to be probing).
func rawRxKey(remoteIP net.IP, remotePort, localPort int) rawRxKeyT {
	k := rawRxKeyT{remotePort: uint16(remotePort), localPort: uint16(localPort)}
	copy(k.ip[:], remoteIP.To4())
	return k
}

// rawRxKeyFromFrame is rawRxKey read straight out of a received segment:
// its IP source (the probed host), its TCP source port (the probed port)
// and its TCP destination port (our source port). The caller has checked
// that the IP and TCP headers fit in buf.
func rawRxKeyFromFrame(buf []byte, ipOffset, tcpOffset int) rawRxKeyT {
	k := rawRxKeyT{
		remotePort: binary.BigEndian.Uint16(buf[tcpOffset : tcpOffset+2]),
		localPort:  binary.BigEndian.Uint16(buf[tcpOffset+2 : tcpOffset+4]),
	}
	copy(k.ip[:], buf[ipOffset+12:ipOffset+16])
	return k
}

// Send path, shared across probes ------------------------------------------
//
// Every probe used to open its own send socket, bind it to -i, look up the
// interface's address (two netlink dumps) and the default route's address
// (a UDP "dial"), send one packet and close the socket: some 25 system
// calls around the one sendto that does the work. Measured with
// BenchmarkRawProbe, that came to about 200 µs of CPU per probe, which is
// why a SYN scan kept five cores busy at 25 000 probes/s. The socket and
// the source address are now set up once and shared.

// rawTxSockets maps an -i value ("" for none) to its send-only raw socket.
// sendto(2) on one raw socket is safe from any number of threads, and the
// socket lives as long as the process, like the shared receive socket.
var (
	rawTxMu      sync.Mutex
	rawTxSockets sync.Map // string -> int (fd)
)

func rawTxSocket(ifaceName string) (int, error) {
	if fd, ok := rawTxSockets.Load(ifaceName); ok {
		return fd.(int), nil
	}
	rawTxMu.Lock()
	defer rawTxMu.Unlock()
	if fd, ok := rawTxSockets.Load(ifaceName); ok {
		return fd.(int), nil
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return -1, fmt.Errorf("raw Socket error (sudo required): %v", err)
	}
	tuneRawTxBuffer(fd)
	if ifaceName != "" {
		if err := netiface.BindToDevice(fd, ifaceName); err != nil {
			fmt.Printf("%s[!] Warning: could not bind raw send socket to interface %q: %v%s\n", config.Red, ifaceName, err, config.Reset)
		}
	}
	rawTxSockets.Store(ifaceName, fd)
	return fd, nil
}

// srcIPTTL is how long a resolved source address is reused. A scan
// resolves it a handful of times instead of once per probe, and the
// long-running web server still follows an address change within seconds.
const srcIPTTL = 5 * time.Second

type srcIPEntry struct {
	ip net.IP
	at time.Time
}

var (
	srcIPMu    sync.Mutex
	srcIPCache sync.Map // string (-i value) -> srcIPEntry
)

// probeSourceIP is the address probes are sent from: the IPv4 address of
// the -i interface when there is one, else that of the default route. The
// returned slice is shared; callers must not modify it.
func probeSourceIP(ifaceName string) net.IP {
	if v, ok := srcIPCache.Load(ifaceName); ok {
		if e := v.(srcIPEntry); time.Since(e.at) < srcIPTTL {
			return e.ip
		}
	}
	// One resolution at a time, so that an expiry doesn't send every worker
	// into its own netlink dump at once.
	srcIPMu.Lock()
	defer srcIPMu.Unlock()
	if v, ok := srcIPCache.Load(ifaceName); ok {
		if e := v.(srcIPEntry); time.Since(e.at) < srcIPTTL {
			return e.ip
		}
	}
	ip := getLocalIPv4()
	if ifaceName != "" {
		if ifaceIP, _, err := netiface.Lookup(ifaceName); err == nil {
			ip = ifaceIP
		}
	}
	srcIPCache.Store(ifaceName, srcIPEntry{ip: ip, at: time.Now()})
	return ip
}

func ensureRawRxLoop(ifaceName string) error {
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
		// This shared RX socket is created once per process (sync.Once), so
		// whichever -i the first scan job passes in wins for the process's
		// lifetime -- fine for a single CLI invocation, which has exactly
		// one -i value throughout.
		tuneRawRxBuffer(fd)
		if ifaceName != "" {
			if err := netiface.BindToDevice(fd, ifaceName); err != nil {
				fmt.Printf("%s[!] Warning: could not bind raw receive socket to interface %q: %v%s\n", config.Red, ifaceName, err, config.Reset)
			}
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

		chAny, ok := rawRxWaiters.Load(rawRxKeyFromFrame(buf, ipOffset, tcpOffset))
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
			Frame:      append([]byte(nil), buf[:n]...),
			IPStart:    ipOffset,
			TCPStart:   tcpOffset,
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

	ifaceName := ""
	if opts != nil {
		ifaceName = opts.Interface
	}

	if err := ensureRawRxLoop(ifaceName); err != nil {
		return nil, err
	}

	srcIP := probeSourceIP(ifaceName)
	if spoofedSrcIP != nil {
		srcIP = spoofedSrcIP.To4()
	}

	fd, err := rawTxSocket(ifaceName)
	if err != nil {
		return nil, err
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
		mptcp:   opts != nil && opts.MPTCP,
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

	// A SYN advertises the standard option set so the SYN/ACK coming back
	// reflects the target's stack rather than this probe's own minimalism
	// (see tcp_options.go). Every other probe type stays a bare 20-byte
	// header: nothing is being negotiated there.
	isSYN := flags == 0x02
	headerLen := 20
	if isSYN {
		headerLen = synTCPHeaderLen
		if s.mptcp {
			headerLen = synMPTCPHeaderLen
		}
	}

	// The whole probe is built in one stack buffer: [outer IPv4 header, for
	// IP-in-IP relaying][IPv4 header][TCP header]. It used to allocate the
	// TCP header, the IP header, their concatenation, the checksum's
	// pseudo-header and the destination address, for every probe.
	var buf [rawMaxPacket]byte
	off := 0
	if s.relayIP != nil {
		off = 20
	}
	ipHeader := buf[off : off+20]
	tcpHeader := buf[off+20 : off+20+headerLen]

	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(s.srcPort))
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(s.dstPort))
	binary.BigEndian.PutUint32(tcpHeader[4:8], 1)
	binary.BigEndian.PutUint32(tcpHeader[8:12], 1)
	tcpHeader[12] = 0x50
	if isSYN {
		if s.mptcp {
			tcpHeader[12] = synMPTCPDataOffset
			writeSYNOptionsMPTCP(tcpHeader[20:])
		} else {
			tcpHeader[12] = synDataOffset
			writeSYNOptions(tcpHeader[20:])
		}
	}
	tcpHeader[13] = flags
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpChecksum(s.srcIP, s.dstIP, tcpHeader))

	putIPv4Header(ipHeader, s.srcIP, s.dstIP, syscall.IPPROTO_TCP, uint16(headerLen))
	packet := buf[off : off+20+headerLen]
	dst := s.dstIP
	if s.relayIP != nil {
		putIPv4Header(buf[0:20], probeSourceIP(""), s.relayIP, syscall.IPPROTO_IPIP, uint16(20+headerLen))
		packet = buf[0 : 40+headerLen]
		dst = s.relayIP
	}
	copy(s.sa.Addr[:], dst.To4())

	s.t0 = time.Now()
	return syscall.Sendto(s.fd, packet, 0, &s.sa)
}

// rawMaxPacket is the largest probe Send builds: an outer IPv4 header (for
// IP-in-IP relaying), the IPv4 header, and the longest TCP header (a SYN
// that carries MP_CAPABLE).
const rawMaxPacket = 20 + 20 + synMPTCPHeaderLen

// putIPv4Header writes a 20-byte IPv4 header into h, checksum included.
func putIPv4Header(h []byte, srcIP, dstIP net.IP, protocol byte, payloadLen uint16) {
	h[0] = 0x45
	h[1] = 0x00
	binary.BigEndian.PutUint16(h[2:4], 20+payloadLen)
	binary.BigEndian.PutUint16(h[4:6], 0x0000)
	binary.BigEndian.PutUint16(h[6:8], 0x4000)
	h[8] = 64
	h[9] = protocol
	binary.BigEndian.PutUint16(h[10:12], 0x0000)
	copy(h[12:16], srcIP.To4())
	copy(h[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(h[10:12], calcIPChecksum(h[:20]))
}

// tcpChecksum is the TCP checksum of seg over the IPv4 pseudo-header
// (source, destination, protocol, length), summed in place instead of
// copying both into a pseudo-header buffer.
func tcpChecksum(srcIP, dstIP net.IP, seg []byte) uint16 {
	src, dst := srcIP.To4(), dstIP.To4()
	sum := uint32(src[0])<<8 | uint32(src[1])
	sum += uint32(src[2])<<8 | uint32(src[3])
	sum += uint32(dst[0])<<8 | uint32(dst[1])
	sum += uint32(dst[2])<<8 | uint32(dst[3])
	sum += 6 // protocol: TCP
	sum += uint32(len(seg))
	for i := 0; i+1 < len(seg); i += 2 {
		sum += uint32(seg[i])<<8 | uint32(seg[i+1])
	}
	if len(seg)%2 == 1 {
		sum += uint32(seg[len(seg)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

func constructIPv4Header(srcIP, dstIP net.IP, protocol byte, payloadLen uint16) []byte {
	header := make([]byte, 20)
	putIPv4Header(header, srcIP, dstIP, protocol, payloadLen)
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
	t := time.NewTimer(s.timeout)
	defer t.Stop()
	select {
	case pkt := <-s.rxChan:
		return pkt, nil
	case <-t.C:
		return nil, fmt.Errorf("timeout waiting for response")
	}
}

func (s *rawTCPScanner) Latency() time.Duration {
	return time.Since(s.t0)
}

// Close releases the probe's reply slot. The send socket is shared across
// probes (see rawTxSocket) and stays open.
func (s *rawTCPScanner) Close() {
	rawRxWaiters.Delete(s.rxKey)
}

func calcTCPChecksum(srcIP, dstIP net.IP, tcpHeader []byte) uint16 {
	return tcpChecksum(srcIP, dstIP, tcpHeader)
}
