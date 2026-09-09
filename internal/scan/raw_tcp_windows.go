//go:build windows
// +build windows

package scan

import (
	"fmt"
	"net"
	"time"

	"tcpcat/config"
)

type rawTCPPacket struct {
	Flags      byte
	WindowSize uint16
	IPID       uint16
}

type rawTCPScanner struct{}

func newRawTCPScanner(_ string, _ int, _ *config.Options, _ time.Duration, _ net.IP) (*rawTCPScanner, error) {
	return nil, fmt.Errorf("raw TCP scans are not supported on Windows; use TCP Connect scan (-sT)")
}

func (*rawTCPScanner) Send(byte) error {
	return fmt.Errorf("raw TCP scans are not supported on Windows")
}

func (*rawTCPScanner) Receive() (*rawTCPPacket, error) {
	return nil, fmt.Errorf("raw TCP scans are not supported on Windows")
}

func (*rawTCPScanner) Latency() time.Duration {
	return 0
}

func (*rawTCPScanner) Close() {}
