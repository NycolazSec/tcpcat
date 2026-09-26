//go:build linux

package discovery

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"tcpcat/internal/netiface"
)

var broadcastMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func htons(x uint16) uint16 {
	return (x << 8) | (x >> 8)
}

// buildARPRequest builds a broadcast Ethernet+ARP "who has dstIP" frame.
func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	frame := make([]byte, 14+28)
	copy(frame[0:6], broadcastMAC[:])
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)

	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800) // protocol type: IPv4
	arp[4] = 6                                   // hardware address length
	arp[5] = 4                                   // protocol address length
	binary.BigEndian.PutUint16(arp[6:8], 1)      // operation: request
	copy(arp[8:14], srcMAC)
	copy(arp[14:18], srcIP)
	// Target hardware address (arp[18:24]) stays zeroed: unknown, that's
	// exactly what this request is resolving.
	copy(arp[24:28], dstIP)
	return frame
}

// ARPScan sends a broadcast ARP "who-has" request for every IP in ips over
// ifaceName and returns whichever answered within timeout.
//
// ARP never crosses a router -- the caller must only pass targets inside
// ifaceName's own subnet -- but for those it's authoritative: a host that
// can't be reached over IP at all still has to answer ARP to receive
// *anything* on its local segment, and a host that genuinely doesn't
// answer ARP can't be reached by a follow-up ICMP/TCP probe either (the
// kernel itself has no way to address a frame at it). That makes an ARP
// sweep both faster than shelling out to ping(1) per host -- no external
// process, no per-host serialization -- and strictly more reliable, since
// it can't be dropped by a target-side firewall the way ICMP/TCP can.
//
// A non-nil error means the raw socket couldn't be used at all (missing
// CAP_NET_RAW, no such interface, ...): the returned map is empty and the
// caller should fall back to the regular ping-based path for every IP,
// not treat the empty result as "all down".
func ARPScan(ips []string, ifaceName string, timeout time.Duration) (map[string]bool, error) {
	alive := make(map[string]bool)
	if len(ips) == 0 {
		return alive, nil
	}
	if ifaceName == "" {
		return alive, fmt.Errorf("ARP scan needs a known interface")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return alive, err
	}
	if iface.HardwareAddr == nil {
		return alive, fmt.Errorf("interface %q has no hardware address", ifaceName)
	}
	srcIP, _, err := netiface.Lookup(ifaceName)
	if err != nil || srcIP.To4() == nil {
		return alive, fmt.Errorf("could not determine an IPv4 address for %q", ifaceName)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return alive, fmt.Errorf("AF_PACKET raw socket error (CAP_NET_RAW/root required): %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  iface.Index,
	}); err != nil {
		return alive, fmt.Errorf("failed to bind ARP socket to %q: %w", ifaceName, err)
	}

	// A short per-read timeout, not a single blocking Recvfrom, so the RX
	// goroutine below can periodically notice the overall deadline instead
	// of potentially blocking well past it if no more replies ever arrive.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 20000})

	txAddr := &unix.SockaddrLinklayer{Ifindex: iface.Index, Halen: 6}
	copy(txAddr.Addr[:6], broadcastMAC[:])

	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64)
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil || n < 14+28 {
				continue
			}
			if binary.BigEndian.Uint16(buf[12:14]) != 0x0806 { // ethertype: ARP
				continue
			}
			if binary.BigEndian.Uint16(buf[14+6:14+8]) != 2 { // ARP opcode: reply
				continue
			}
			senderIP := net.IP(append([]byte(nil), buf[14+14:14+18]...)).String()
			mu.Lock()
			alive[senderIP] = true
			mu.Unlock()
		}
	}()

	srcMAC := iface.HardwareAddr
	for _, ipStr := range ips {
		dstIP := net.ParseIP(ipStr).To4()
		if dstIP == nil {
			continue
		}
		frame := buildARPRequest(srcMAC, srcIP.To4(), dstIP)
		_ = unix.Sendto(fd, frame, 0, txAddr)
	}

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	result := make(map[string]bool, len(alive))
	for k, v := range alive {
		result[k] = v
	}
	return result, nil
}
