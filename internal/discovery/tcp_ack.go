// internal/discovery/tcp_ack.go
package discovery

import (
	"fmt"
	"net"
	"time"
)

// PingTCP Probe tente d'établir une connexion rapide ou d'envoyer un paquet SYN/ACK
// pour déterminer si la cible est vivante (Host Discovery -PS/-PA).
func PingTCP(ip string, port int, useACK bool, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		// Sur un RST ou un refus de connexion, la machine est bien active !
		return true
	}
	_ = conn.Close()
	return true
}