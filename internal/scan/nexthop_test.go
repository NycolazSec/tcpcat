package scan

import (
	"net"
	"testing"
)

const procRoute = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0100C80A	0003	0	0	0	00000000	0	0	0
eth0	0000C80A	00000000	0001	0	0	0	00FFFFFF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`

const procARP = `IP address       HW type     Flags       HW address            Mask     Device
10.200.0.20      0x1         0x2         02:42:0a:c8:00:14     *        eth0
10.200.0.1       0x1         0x2         02:42:d4:aa:bb:01     *        eth0
10.200.0.21      0x1         0x0         00:00:00:00:00:00     *        eth0
172.17.0.5       0x1         0x2         02:42:ac:11:00:05     *        docker0
`

func TestParseDefaultGateway(t *testing.T) {
	if gw := parseDefaultGateway(procRoute, "eth0"); gw.String() != "10.200.0.1" {
		t.Errorf("eth0 gateway = %v, want 10.200.0.1", gw)
	}
	if gw := parseDefaultGateway(procRoute, "docker0"); gw != nil {
		t.Errorf("docker0 has no default route, got %v", gw)
	}
}

func TestLookupARPTable(t *testing.T) {
	if mac := lookupARPTable(procARP, "eth0", "10.200.0.20"); mac.String() != "02:42:0a:c8:00:14" {
		t.Errorf("mac = %v", mac)
	}
	if mac := lookupARPTable(procARP, "eth0", "10.200.0.21"); mac != nil {
		t.Errorf("an incomplete entry must not be used, got %v", mac)
	}
	if mac := lookupARPTable(procARP, "eth0", "172.17.0.5"); mac != nil {
		t.Errorf("an entry on another interface must not be used, got %v", mac)
	}
}

// The bug this replaces: every frame went to "the first ARP entry on the
// interface", so an on-link target other than that one never got its SYNs.
func TestNextHopIP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.200.0.0/24")
	gw := net.ParseIP("10.200.0.1")
	if hop := nextHopIP(net.ParseIP("10.200.0.21"), subnet, gw); hop.String() != "10.200.0.21" {
		t.Errorf("on-link target: next hop = %v, want the target itself", hop)
	}
	if hop := nextHopIP(net.ParseIP("203.0.113.9"), subnet, gw); hop.String() != "10.200.0.1" {
		t.Errorf("off-link target: next hop = %v, want the gateway", hop)
	}
	if hop := nextHopIP(net.ParseIP("203.0.113.9"), subnet, nil); hop != nil {
		t.Errorf("off-link target without a gateway: next hop = %v, want nil", hop)
	}
}
