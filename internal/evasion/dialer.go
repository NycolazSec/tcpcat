// internal/evasion/dialer.go
package evasion

import (
	"net"
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

// Dial tente la connexion avec le port source spécifié, puis bascule si le port est occupé.
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

				// Note: SO_REUSEPORT est omis pour une meilleure portabilité.
				// Sa valeur et sa disponibilité varient considérablement entre les OS (Linux, macOS, BSDs).
				// La logique de fallback du dialer gère déjà les cas où le port source est occupé.

				if d.Config != nil && d.Config.TTL > 0 {
					_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, d.Config.TTL)
				}
			})
		},
	}

	conn, err := netDialer.Dial(network, address)

	// Fallback : Si le port source spécifié est bloqué/occupé, retente sans forcer le port local
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
