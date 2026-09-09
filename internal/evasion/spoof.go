package evasion

import (
	"fmt"
	"net"
)

type SpoofConfig struct {
	SourceIP   net.IP
	SourceMAC  net.HardwareAddr
	EnabledIP  bool
	EnabledMAC bool
}

func ParseMACAddress(macStr string) (net.HardwareAddr, error) {
	if macStr == "" {
		return nil, nil
	}
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address: %v", err)
	}
	return mac, nil
}
