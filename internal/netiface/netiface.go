// Package netiface resolves a network interface chosen explicitly by the
// operator (-i/--interface) into the concrete IP/subnet/MAC details the
// scan engines need, instead of always relying on default-route
// auto-detection (getDefaultNetworkInfo in internal/scan/xdp.go). This
// matters for targets reachable only through a local virtual interface --
// a Docker bridge (br-*), a VPN tunnel, or a secondary NIC -- which is
// never the default gateway's interface and so is invisible to
// auto-detection.
package netiface

import (
	"fmt"
	"net"
)

// Lookup validates that ifaceName exists and returns its first IPv4
// address and subnet, read directly from the interface rather than
// inferred from the default route.
func Lookup(ifaceName string) (net.IP, *net.IPNet, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, nil, fmt.Errorf("network interface %q not found: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read addresses for interface %q: %w", ifaceName, err)
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				return ip4, ipNet, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("interface %q has no IPv4 address assigned", ifaceName)
}

// MAC returns the interface's own hardware address.
func MAC(ifaceName string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("network interface %q not found: %w", ifaceName, err)
	}
	return iface.HardwareAddr, nil
}

// DefaultInterfaceName reports the name of the interface the default route
// would send traffic through -- the same interface auto-detection (no
// -i/--interface given) ends up using, resolved cheaply here (no packets
// sent) purely for cosmetic/display purposes, e.g. showing the operator
// which interface is actually in play instead of a generic placeholder.
func DefaultInterfaceName() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", fmt.Errorf("no route to determine a default interface: %w", err)
	}
	defer func() { _ = conn.Close() }()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", fmt.Errorf("could not determine local address")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && ipNet.IP.Equal(localAddr.IP) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface owns local address %s", localAddr.IP)
}
