//go:build linux

package scan

import (
	"net"
	"os"
	"time"

	"github.com/asavie/xdp"
)

// DiscoverHostsXDP fires ICMP Echo, TCP SYN/443, and TCP ACK/80 probes for
// every candidate IP over the already-initialized AF_XDP engine -- plus an
// ARP request for any candidate that falls inside the interface's own
// subnet, since a host with every routable probe firewalled off still has
// to answer ARP to receive any traffic at all on its local segment -- then
// collects whichever hosts answered any of them before timeout elapses.
// xdpRxLoop records the replies into xdpDiscovery as they arrive, so this
// function only has to fire the probes and wait: no per-host blocking dial,
// no shelling out to ping/arping, and no state beyond that one shared map.
//
// limiter paces emission (nil disables pacing) so a sweep over a large
// range honours --rate rather than sending as fast as the TX ring drains.
func DiscoverHostsXDP(ips []string, timeout time.Duration, limiter *AdaptiveRateLimiter) []string {
	xsk, ok := GlobalXsk.(*xdp.Socket)
	if !ok || xsk == nil {
		return nil
	}

	for _, ip := range ips {
		xdpDiscovery.Delete(ip) // drop any stale result from a previous run
	}

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
			constructSYNFrame(localMAC, gatewayMAC, localIP.To4(), targetIP, xdpDiscoverySrcPort, 443, false),
			constructACKFrame(localMAC, gatewayMAC, localIP.To4(), targetIP, xdpDiscoverySrcPort, 80),
		}
		if localSubnet != nil && localSubnet.Contains(targetIP) {
			frames = append(frames, constructARPRequestFrame(localMAC, localIP.To4(), targetIP))
		}

		// Reserve one pacer slot per frame actually about to go out, the
		// same accounting the scan engine uses, so a /16 discovery sweep
		// respects --rate instead of emitting 3-4 frames per host as fast
		// as the ring drains.
		if limiter != nil {
			limiter.WaitN(len(frames))
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
