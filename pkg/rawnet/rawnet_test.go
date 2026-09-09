package rawnet

import (
	"net"
	"testing"
)

func TestChecksum(t *testing.T) {

	sampleData := []byte{
		0x45, 0x00, 0x00, 0x3c,
		0x1c, 0x46, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		0xac, 0x10, 0x0a, 0x63,
		0xac, 0x10, 0x0a, 0x0c,
	}

	cs := Checksum(sampleData)
	if cs == 0 {
		t.Errorf("Échec : Le checksum calculé ne devrait pas être nul")
	}
	t.Logf("Checksum calculé avec succès : 0x%04x", cs)
}

func TestTCPChecksum(t *testing.T) {
	srcIP := net.ParseIP("127.0.0.1")
	dstIP := net.ParseIP("127.0.0.1")

	tcpHeader := []byte{
		0x15, 0xb3,
		0x00, 0x50,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02,
		0xfa, 0xf0,
		0x00, 0x00,
		0x00, 0x00,
	}

	payload := []byte{}

	cs := TCPChecksum(srcIP, dstIP, tcpHeader, payload)
	if cs == 0 {
		t.Errorf("Échec : Le checksum TCP calculé est invalide")
	}
	t.Logf("Checksum TCP calculé avec succès : 0x%04x", cs)
}

func TestRawSocketInit(t *testing.T) {
	sock, err := NewRawSocket(6)
	if err != nil {
		t.Skipf("Test ignoré (privilèges root/sudo requis) : %v", err)
		return
	}
	defer sock.Close()

	if sock.fd <= 0 {
		t.Errorf("Descripteur de fichier de socket invalide : %d", sock.fd)
	}
}
