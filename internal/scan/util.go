package scan

import (
	"net"
)

func getLocalIPv4() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.ParseIP("127.0.0.1").To4()
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.To4()
}
