//go:build windows

package evasion

import (
	"net"
	"time"
)

type CustomDialer struct {
	Config  *Config
	Timeout time.Duration
}

func NewCustomDialer(cfg *Config, timeout time.Duration) *CustomDialer {
	return &CustomDialer{Config: cfg, Timeout: timeout}
}

func (d *CustomDialer) Dial(network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.Timeout}
	if d.Config != nil && d.Config.SourcePort > 0 {
		dialer.LocalAddr = &net.TCPAddr{Port: d.Config.SourcePort}
	}
	conn, err := dialer.Dial(network, address)
	if err != nil && d.Config != nil && d.Config.SourcePort > 0 {
		return (&net.Dialer{Timeout: d.Timeout}).Dial(network, address)
	}
	if err != nil {
		return nil, err
	}
	if d.Config != nil && len(d.Config.Payload) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write(d.Config.Payload)
	}
	return conn, nil
}
