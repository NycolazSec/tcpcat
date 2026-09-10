//go:build linux

package scan

import (
	"net"
	"os"
	"time"

	"github.com/asavie/xdp"
)

// DiscoverHostsXDP fires ICMP Echo, TCP SYN/443, and TCP ACK/80 probes for
// every candidate IP over the already-initialized AF_XDP engine, then
// collects whichever hosts answered any of them before timeout elapses.
// xdpRxLoop records the replies into xdpDiscovery as they arrive, so this
// function only has to fire the probes and wait: no per-host blocking dial,
// no shelling out to ping, and no state beyond that one shared map.
func DiscoverHostsXDP(ips []string, timeout time.Duration) []string {
	xsk, ok := GlobalXsk.(*xdp.Socket)
	if !ok || xsk == nil {
		return nil
	}

	for _, ip := range ips {
		xdpDiscovery.Delete(ip) // drop any stale result from a previous run
	}

	const discoverySrcPort = 54322
	icmpID := uint16(os.Getpid() & 0xffff)

	for i, ipStr := range ips {
		targetIP := net.ParseIP(ipStr)
		if targetIP == nil {
			continue
		}
		targetIP = targetIP.To4()
		if targetIP == nil {
			continue // IPv6 targets aren't supported by this frame layout
		}

		frames := [][]byte{
			constructICMPEchoFrame(localMAC, gatewayMAC, localIP.To4(), targetIP, icmpID, uint16(i)),
			constructSYNFrame(localMAC, gatewayMAC, localIP.To4(), targetIP, discoverySrcPort, 443),
			constructACKFrame(localMAC, gatewayMAC, localIP.To4(), targetIP, discoverySrcPort, 80),
		}

		xdpTxLock.Lock()
		for _, frame := range frames {
			descs := xsk.GetDescs(1)
			if len(descs) == 0 {
				continue // TX ring momentarily full; this host just gets fewer probe types
			}
			copy(xsk.GetFrame(descs[0]), frame)
			descs[0].Len = uint32(len(frame))
			xsk.Transmit(descs)
		}
		xdpTxLock.Unlock()
	}

	time.Sleep(timeout)

	var alive []string
	for _, ip := range ips {
		if _, ok := xdpDiscovery.Load(ip); ok {
			alive = append(alive, ip)
		}
	}
	return alive
}
