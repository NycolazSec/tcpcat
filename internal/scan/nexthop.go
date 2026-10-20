package scan

import (
	"encoding/hex"
	"net"
	"strings"
)

// Which machine an Ethernet frame must be addressed to so that it reaches
// its IP destination: the destination itself when it sits on the sending
// interface's own network, the default gateway otherwise. The AF_XDP engine
// builds its own frames, so it has to answer this itself -- the kernel's
// routing and neighbour tables aren't consulted on that path.

// nextHopIP returns the address whose MAC a frame for target needs. nil
// means "unknown": no gateway is configured for an off-link target.
func nextHopIP(target net.IP, subnet *net.IPNet, gateway net.IP) net.IP {
	if subnet != nil && subnet.Contains(target) {
		return target
	}
	return gateway
}

// parseDefaultGateway reads the default route's gateway for iface out of the
// content of /proc/net/route (addresses there are little-endian hex).
func parseDefaultGateway(routeTable, iface string) net.IP {
	for _, line := range strings.Split(routeTable, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != iface || f[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 || f[2] == "00000000" {
			continue
		}
		return net.IPv4(raw[3], raw[2], raw[1], raw[0])
	}
	return nil
}

// lookupARPTable finds ip's hardware address on iface in the content of
// /proc/net/arp. Incomplete entries (all-zero MAC) don't count.
func lookupARPTable(arpTable, iface, ip string) net.HardwareAddr {
	for _, line := range strings.Split(arpTable, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 6 || f[0] != ip || f[5] != iface || f[3] == "00:00:00:00:00:00" {
			continue
		}
		if mac, err := net.ParseMAC(f[3]); err == nil {
			return mac
		}
	}
	return nil
}
