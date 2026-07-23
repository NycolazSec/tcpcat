// internal/discovery/udp_sctp.go
package discovery

import (
	"fmt"
	"net"
	"time"
)

// PingUDP envoie une sonde UDP vers le port spécifié (-PU).
// Si l'hôte répond ou renvoie un rejet ICMP (Port Unreachable), l'hôte est considéré actif.
func PingUDP(ip string, port int, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// 1. Envoi d'un octet de sonde UDP
	probeData := []byte{0x00}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	_, err = conn.Write(probeData)
	if err != nil {
		return false
	}

	// 2. Lecture de la réponse éventuelle
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)

	if err != nil {
		// En cas de timeout, le résultat UDP reste indéterminé
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false
		}
		// Toute autre erreur (ex: connection refused / ICMP port unreachable) atteste que l'hôte est vivant
		return true
	}

	// Réponse explicite reçue
	return true
}

// PingSCTP tente une sonde de découverte d'hôte via la pile SCTP (-PY).
func PingSCTP(ip string, port int, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%d", ip, port)

	// Tentative d'initialisation via le driver protocole du système
	conn, err := net.DialTimeout("sctp", target, timeout)
	if err != nil {
		// Une erreur de refus active signale également la présence de l'hôte
		if netErr, ok := err.(net.Error); ok && !netErr.Timeout() {
			return true
		}
		return false
	}

	_ = conn.Close()
	return true
}