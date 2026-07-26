package scan

import (
	"fmt"
	"time"

	"tcpcat/config"
)

type StealthType int

const (
	ScanNull StealthType = iota
	ScanFin
	ScanXmas
)

func ScanStealthPort(targetIP string, port int, scanType StealthType, opts *config.Options, timeout time.Duration) TargetResult {
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

	var flags byte
	switch scanType {
	case ScanNull:
		flags = 0x00
	case ScanFin:
		flags = 0x01
	case ScanXmas:
		flags = 0x29
	}

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
