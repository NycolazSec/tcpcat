package scan

import (
	"fmt"
	"time"

	"tcpcat/config"
)

func ScanSYNPort(targetIP string, port int, opts *config.Options, timeout time.Duration) TargetResult {
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

	err = scanner.Send(0x02)
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
		res.Reason = "No response / Timeout"
		return res
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
