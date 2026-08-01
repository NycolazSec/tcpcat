//go:build !linux

package scan

import (
	"fmt"
	"time"

	"tcpcat/config"
)

// GlobalXsk is a stub for non-Linux systems.
var GlobalXsk any

// InitXDPEngine is a stub for non-Linux systems.
func InitXDPEngine() (any, error) {
	return nil, fmt.Errorf("le moteur AF_XDP/eBPF n'est supporté que sur Linux")
}

// ShutdownXDPEngine is a stub for non-Linux systems.
func ShutdownXDPEngine() {
	// Rien à faire sur les systèmes non-Linux
}

// ScanXDPPort is a stub for non-Linux systems.
func ScanXDPPort(ip string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	return TargetResult{IP: ip, Port: port, State: StateFiltered, Reason: "XDP non supporté"}
}

// ScanXDPUDPPort is a stub for non-Linux systems.
func ScanXDPUDPPort(ip string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	return TargetResult{IP: ip, Port: port, State: StateFiltered, Reason: "XDP non supporté"}
}
