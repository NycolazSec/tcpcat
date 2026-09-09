package scan

import (
	"fmt"
	"net"
	"time"

	"tcpcat/config"
	"tcpcat/internal/evasion"
)

func ScanAckPort(targetIP string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, relayIP net.IP) TargetResult {
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
					_ = scanner.Send(0x10)
				}(decoyIP)
			}
		}
	}

	scanner, err := newRawTCPScanner(targetIP, port, opts, timeout, spoofedSrcIP)
	if err != nil {
		res.State = StateFiltered
		res.Reason = err.Error()
		return res
	}
	defer scanner.Close()

	err = scanner.Send(0x10)
	if err != nil {
		res.State = StateFiltered
		res.Reason = fmt.Sprintf("Send failed: %v", err)
		return res
	}

	resp, err := scanner.Receive()
	res.Latency = scanner.Latency()
	res.LatencyMs = float64(res.Latency.Microseconds()) / 1000.0

	if err != nil {
		res.State = StateFiltered
		res.Reason = "No response (Stateful Firewall)"
		return res
	}

	if resp.Flags&0x04 != 0 {
		res.State = StateUnfiltered
		res.Reason = "RST Received (Unfiltered)"
	}
	return res
}

func ScanWindowPort(targetIP string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, relayIP net.IP) TargetResult {
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
					_ = scanner.Send(0x10)
				}(decoyIP)
			}
		}
	}

	scanner, err := newRawTCPScanner(targetIP, port, opts, timeout, spoofedSrcIP)
	if err != nil {
		res.State = StateFiltered
		res.Reason = err.Error()
		return res
	}
	defer scanner.Close()

	err = scanner.Send(0x10)
	if err != nil {
		res.State = StateFiltered
		res.Reason = fmt.Sprintf("Send failed: %v", err)
		return res
	}

	resp, err := scanner.Receive()
	res.Latency = scanner.Latency()
	res.LatencyMs = float64(res.Latency.Microseconds()) / 1000.0

	if err != nil {
		res.State = StateFiltered
		res.Reason = "No response (Stateful Firewall)"
		return res
	}

	if resp.Flags&0x04 != 0 {
		if resp.WindowSize > 0 {
			res.State = StateOpen
			res.Reason = "RST received with non-zero window size"
		} else {
			res.State = StateClosed
			res.Reason = "RST received with zero window size"
		}
	}

	return res
}
