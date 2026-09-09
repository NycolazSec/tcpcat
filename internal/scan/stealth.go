package scan

import (
	"fmt"
	"net"
	"time"

	"tcpcat/config"
	"tcpcat/internal/evasion"
)

type StealthType int

const (
	ScanNull StealthType = iota
	ScanFin
	ScanXmas
)

func ScanStealthPort(targetIP string, port int, scanType StealthType, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, relayIP net.IP) TargetResult {
	res := TargetResult{
		IP:   targetIP,
		Port: port,
	}

	var flags byte
	switch scanType {
	case ScanNull:
		flags = 0x00
	case ScanFin:
		flags = 0x01
	case ScanXmas:
		flags = 0x29
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
					_ = scanner.Send(flags)
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

	err = scanner.Send(flags)
	if err != nil {
		res.State = StateFiltered
		res.Reason = fmt.Sprintf("Send failed: %v", err)
		return res
	}

	resp, err := scanner.Receive()
	res.Latency = scanner.Latency()
	res.LatencyMs = float64(res.Latency.Microseconds()) / 1000.0

	if err != nil {
		res.State = StateOpenFiltered
		res.Reason = "No RST received (RFC 793 Open|Filtered)"
		return res
	}

	if resp.Flags&0x04 != 0 {
		res.State = StateClosed
		res.Reason = "RST Received (Closed)"
	}
	return res
}
