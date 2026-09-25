//go:build !linux

package scan

import (
	"fmt"
	"time"

	"net"
	"tcpcat/config"
)

var GlobalXsk any

func InitXDPEngine(ifaceName string) (any, error) {
	return nil, fmt.Errorf("the AF_XDP/eBPF engine is only supported on Linux")
}

func ShutdownXDPEngine() {

}

func ScanXDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, rtt *RTTEstimator) TargetResult {
	return TargetResult{IP: ip, Port: port, State: StateFiltered, Reason: "XDP non supporté"}
}

func ScanXDPUDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, rtt *RTTEstimator) TargetResult {
	return TargetResult{IP: ip, Port: port, State: StateFiltered, Reason: "XDP non supporté"}
}

func DiscoverHostsXDP(ips []string, timeout time.Duration, limiter *AdaptiveRateLimiter) []string {
	return nil
}
