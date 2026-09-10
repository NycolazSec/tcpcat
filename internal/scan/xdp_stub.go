//go:build !linux

package scan

import (
	"fmt"
	"time"

	"net"
	"tcpcat/config"
)

var GlobalXsk any

func InitXDPEngine() (any, error) {
	return nil, fmt.Errorf("le moteur AF_XDP/eBPF n'est supporté que sur Linux")
}

func ShutdownXDPEngine() {

}

func ScanXDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP) TargetResult {
	return TargetResult{IP: ip, Port: port, State: StateFiltered, Reason: "XDP non supporté"}
}

func ScanXDPUDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP) TargetResult {
	return TargetResult{IP: ip, Port: port, State: StateFiltered, Reason: "XDP non supporté"}
}

func DiscoverHostsXDP(ips []string, timeout time.Duration) []string {
	return nil
}
