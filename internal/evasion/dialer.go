//go:build !windows

package evasion

import (
	"net"
	"strings"
	"syscall"
	"time"
)

type CustomDialer struct {
	Config  *Config
	Timeout time.Duration
}

func NewCustomDialer(cfg *Config, timeout time.Duration) *CustomDialer {
	return &CustomDialer{
		Config:  cfg,
		Timeout: timeout,
	}
}

func (d *CustomDialer) Dial(network, address string) (net.Conn, error) {
	var localAddr net.Addr
	if d.Config != nil && d.Config.SourcePort > 0 {
		localAddr = &net.TCPAddr{Port: d.Config.SourcePort}
	}

	netDialer := &net.Dialer{
		Timeout:   d.Timeout,
		LocalAddr: localAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)

				if d.Config != nil && d.Config.TTL > 0 {
					if strings.Contains(network, "6") {
						// network is the resolved "tcp6"/"udp6" etc. Dialer.Control
						// passes in -- IP_TTL is the wrong sockopt level for an
						// IPv6 socket (it silently no-ops there); the IPv6
						// equivalent is IPV6_UNICAST_HOPS at IPPROTO_IPV6.
						_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, d.Config.TTL)
					} else {
						_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, d.Config.TTL)
					}
				}
			})
		},
	}

	conn, err := netDialer.Dial(network, address)

	if err != nil && localAddr != nil {
		fallbackDialer := &net.Dialer{Timeout: d.Timeout}
		return fallbackDialer.Dial(network, address)
	}

	if err != nil {
		return nil, err
	}

	if d.Config != nil && len(d.Config.Payload) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, _ = conn.Write(d.Config.Payload)
	}

	return conn, nil
}
