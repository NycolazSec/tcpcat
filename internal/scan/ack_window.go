package scan

import (
	"fmt"
	"time"

	"tcpcat/config"
)

func ScanAckPort(targetIP string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	res := TargetResult{
		IP:   targetIP,
		Port: port,
	}

	scanner, err := newRawTCPScanner(targetIP, port, opts, timeout, nil)
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

func ScanWindowPort(targetIP string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	res := TargetResult{
		IP:   targetIP,
		Port: port,
	}

	scanner, err := newRawTCPScanner(targetIP, port, opts, timeout, nil)
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
