// internal/evasion/decoy.go
package evasion

import "net"

type DecoyConfig struct {
	DecoyIPs []net.IP // Nécessite moteur Raw Socket
	Enabled  bool
}