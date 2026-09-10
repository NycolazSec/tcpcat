package scan

import (
	"fmt"
	"net"
	"time"

	"tcpcat/config"
	"tcpcat/internal/evasion"
)

func ScanSYNPort(targetIP string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, relayIP net.IP, rtt *RTTEstimator) TargetResult {
	res := TargetResult{
		IP:   targetIP,
		Port: port,
	}

	if opts.DecoyIPs != "" {
		decoys, err := evasion.ParseDecoys(opts.DecoyIPs)
		if err == nil {
			for _, decoyIP := range decoys {
				go func(decoyIP net.IP) {
					scanner, err := newRawTCPScanner(targetIP, port, opts, 1*time.Millisecond, decoyIP)
					if err != nil {
						return
					}
					defer scanner.Close()
					_ = scanner.Send(0x02)
				}(decoyIP)
			}
		}
	}

	attemptTimeout := probeTimeout(rtt, timeout)
	scanner, err := newRawTCPScanner(targetIP, port, opts, attemptTimeout, spoofedSrcIP)
	if err != nil {
		res.State = StateFiltered
		res.Reason = err.Error()
		return res
	}
	defer scanner.Close()

	attempts := probeAttempts(opts)
	for attempt := 0; attempt < attempts; attempt++ {
		err = scanner.Send(0x02)
		if err != nil {
			res.State = StateFiltered
			res.Reason = fmt.Sprintf("Send failed: %v", err)
			return res
		}

		resp, recvErr := scanner.Receive()
		res.Latency = scanner.Latency()
		res.LatencyMs = float64(res.Latency.Microseconds()) / 1000.0

		if recvErr != nil {
			res.State = StateFiltered
			res.Reason = "No response / Timeout"
			continue
		}
		if rtt != nil {
			rtt.Sample(res.Latency)
		}

		if resp.Flags&0x12 == 0x12 {
			res.State = StateOpen
			res.Reason = "SYN-ACK Received"
		} else if resp.Flags&0x04 != 0 {
			res.State = StateClosed
			res.Reason = "RST Received"
		}
		return res
	}
	return res
}
