package scan

import (
	"net"
)

// natConnectWorkers caps the connections a connect scan keeps open at once
// when it leaves through a router that translates addresses (a home box).
// Such a router keeps an entry for every connection until it times out, and
// a filtered port never answers: past a few dozen at a time, the entries
// pile up, the router drops or refuses new connections, the scan's own
// included, and every port of the target looks filtered. Measured on a home
// box: 64 at a time filled it within seconds, 32 did not.
const natConnectWorkers = 32

// cgnat is the shared address space carriers use behind their own NAT.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// behindNAT reports whether traffic from local to target goes through
// address translation: a private source reaching a public destination.
func behindNAT(local, target net.IP) bool {
	if local == nil || target == nil {
		return false
	}
	public := !target.IsPrivate() && !target.IsLoopback() && !target.IsLinkLocalUnicast() && !cgnat.Contains(target)
	private := local.IsPrivate() || cgnat.Contains(local)
	return public && private
}

// SourceBehindNAT returns the local address this machine would use to reach
// the first public target, when that address is private: the scan then goes
// through a router that translates addresses. It sends nothing (a UDP
// "connection" only picks a route).
func SourceBehindNAT(targets []string) (net.IP, bool) {
	for _, t := range targets {
		ip := net.ParseIP(t)
		if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip) {
			continue
		}
		c, err := net.Dial("udp", net.JoinHostPort(ip.String(), "9"))
		if err != nil {
			return nil, false
		}
		local := c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
		return local, behindNAT(local, ip)
	}
	return nil, false
}
