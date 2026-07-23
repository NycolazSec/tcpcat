// pkg/rawnet/rawnet_test.go
package rawnet

import (
	"net"
	"testing"
)

// TestChecksum valide le calcul de la somme de contrôle IP/TCP.
func TestChecksum(t *testing.T) {
	// Entête IP factice de 20 octets
	sampleData := []byte{
		0x45, 0x00, 0x00, 0x3c,
		0x1c, 0x46, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00, // Checksum à 0x0000 avant calcul
		0xac, 0x10, 0x0a, 0x63,
		0xac, 0x10, 0x0a, 0x0c,
	}

	cs := Checksum(sampleData)
	if cs == 0 {
		t.Errorf("Échec : Le checksum calculé ne devrait pas être nul")
	}
	t.Logf("Checksum calculé avec succès : 0x%04x", cs)
}

// TestTCPChecksum valide la construction du pseudo-header IPv4 et le calcul du checksum TCP.
func TestTCPChecksum(t *testing.T) {
	srcIP := net.ParseIP("127.0.0.1")
	dstIP := net.ParseIP("127.0.0.1")

	// Header TCP SYN fictif de 20 octets
	tcpHeader := []byte{
		0x15, 0xb3, // Port Source: 5555
		0x00, 0x50, // Port Dest: 80
		0x00, 0x00, 0x00, 0x01, // Seq
		0x00, 0x00, 0x00, 0x00, // Ack
		0x50, 0x02, // Offset & Flags (SYN)
		0xfa, 0xf0, // Window
		0x00, 0x00, // Checksum (vide)
		0x00, 0x00, // Urgent Pointer
	}

	payload := []byte{}

	cs := TCPChecksum(srcIP, dstIP, tcpHeader, payload)
	if cs == 0 {
		t.Errorf("Échec : Le checksum TCP calculé est invalide")
	}
	t.Logf("Checksum TCP calculé avec succès : 0x%04x", cs)
}

// TestRawSocketInit vérifie la création du socket brut avec les privilèges root.
func TestRawSocketInit(t *testing.T) {
	sock, err := NewRawSocket(6) // 6 = IPPROTO_TCP
	if err != nil {
		t.Skipf("Test ignoré (privilèges root/sudo requis) : %v", err)
		return
	}
	defer sock.Close()

	if sock.fd <= 0 {
		t.Errorf("Descripteur de fichier de socket invalide : %d", sock.fd)
	}
}