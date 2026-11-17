//go:build !linux

package scan

import (
	"fmt"
	"time"

	"github.com/NycolazSec/tcpcat/config"
	"net"
)

var GlobalXsk any

func InitXDPEngine(ifaceName string, opts *config.Options) (any, error) {
	return nil, fmt.Errorf("the AF_XDP/eBPF engine is only supported on Linux")
}

func ShutdownXDPEngine() {

}

// XDPCopyMode is false here: there is no AF_XDP engine off Linux.
func XDPCopyMode() bool { return false }

// XDPNotProbed is 0 here: there is no AF_XDP engine off Linux.
func XDPNotProbed() int64 { return 0 }

func ScanXDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, rtt *RTTEstimator, limiter *AdaptiveRateLimiter) TargetResult {
	return TargetResult{IP: ip, Port: port, State: StateFiltered, Reason: "XDP non supporté"}
}

func ScanXDPUDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, rtt *RTTEstimator, limiter *AdaptiveRateLimiter) TargetResult {
	return TargetResult{IP: ip, Port: port, State: StateFiltered, Reason: "XDP non supporté"}
}

func DiscoverHostsXDP(ips []string, timeout time.Duration, limiter *AdaptiveRateLimiter) []string {
	return nil
}
