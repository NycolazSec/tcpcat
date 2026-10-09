package service

import (
	"bufio"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func nameListBytes(items string) []byte {
	b := make([]byte, 4+len(items))
	binary.BigEndian.PutUint32(b[:4], uint32(len(items)))
	copy(b[4:], items)
	return b
}

// buildKexInit assembles a minimal valid KEXINIT payload from the four audited
// name-lists (the others are sent empty).
func buildKexInit(kex, hostKey, ciphers, macs string) []byte {
	var p []byte
	p = append(p, sshMsgKexInit)
	p = append(p, make([]byte, 16)...) // cookie
	p = append(p, nameListBytes(kex)...)
	p = append(p, nameListBytes(hostKey)...)
	p = append(p, nameListBytes(ciphers)...) // enc c2s
	p = append(p, nameListBytes(ciphers)...) // enc s2c (audited)
	p = append(p, nameListBytes(macs)...)    // mac c2s
	p = append(p, nameListBytes(macs)...)    // mac s2c (audited)
	p = append(p, nameListBytes("none")...)  // comp c2s
	p = append(p, nameListBytes("none")...)  // comp s2c
	p = append(p, nameListBytes("")...)      // lang c2s
	p = append(p, nameListBytes("")...)      // lang s2c
	p = append(p, 0)                         // first_kex_packet_follows
	p = append(p, make([]byte, 4)...)        // reserved
	return p
}

func TestParseKexInit(t *testing.T) {
	payload := buildKexInit(
		"curve25519-sha256,diffie-hellman-group1-sha1",
		"rsa-sha2-512,ssh-rsa",
		"chacha20-poly1305@openssh.com,aes128-cbc",
		"hmac-sha2-256,hmac-sha1",
	)
	var info SSHPostureInfo
	parseKexInit(payload, &info)

	if !reflect.DeepEqual(info.KexAlgorithms, []string{"curve25519-sha256", "diffie-hellman-group1-sha1"}) {
		t.Errorf("kex = %v", info.KexAlgorithms)
	}
	if !reflect.DeepEqual(info.Ciphers, []string{"chacha20-poly1305@openssh.com", "aes128-cbc"}) {
		t.Errorf("ciphers = %v", info.Ciphers)
	}
	if !reflect.DeepEqual(info.MACs, []string{"hmac-sha2-256", "hmac-sha1"}) {
		t.Errorf("macs = %v", info.MACs)
	}
}

func TestAnalyzeSSHPostureFlagsWeak(t *testing.T) {
	info := &SSHPostureInfo{
		KexAlgorithms:     []string{"curve25519-sha256", "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"},
		HostKeyAlgorithms: []string{"rsa-sha2-512", "ssh-rsa", "ssh-dss"},
		Ciphers:           []string{"aes256-gcm@openssh.com", "aes128-cbc", "3des-cbc", "arcfour256"},
		MACs:              []string{"hmac-sha2-256", "hmac-sha1", "hmac-md5", "umac-64@openssh.com"},
	}
	analyzeSSHPosture(info)

	joined := strings.Join(info.Warnings, "\n")
	for _, want := range []string{
		"weak key exchange offered: diffie-hellman-group1-sha1, diffie-hellman-group14-sha1",
		"weak host-key algorithm offered: ssh-rsa, ssh-dss",
		"weak cipher offered: aes128-cbc, 3des-cbc, arcfour256",
		"weak MAC offered: hmac-sha1, hmac-md5, umac-64@openssh.com",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning %q in:\n%s", want, joined)
		}
	}
}

func TestAnalyzeSSHPostureStrongIsClean(t *testing.T) {
	info := &SSHPostureInfo{
		KexAlgorithms:     []string{"curve25519-sha256", "diffie-hellman-group-exchange-sha256"},
		HostKeyAlgorithms: []string{"rsa-sha2-512", "ssh-ed25519", "ecdsa-sha2-nistp256"},
		Ciphers:           []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"},
		MACs:              []string{"hmac-sha2-256", "hmac-sha2-512-etm@openssh.com", "umac-128@openssh.com"},
	}
	analyzeSSHPosture(info)
	if len(info.Warnings) != 0 {
		t.Errorf("a strong config should raise no warnings, got %v", info.Warnings)
	}
}

func TestSSHProtocolVersion(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_9.6": "2.0",
		"SSH-1.99-OpenSSH":    "1.99",
		"SSH-1.5-OldServer":   "1.5",
	}
	for ident, want := range cases {
		if got := sshProtocolVersion(ident); got != want {
			t.Errorf("sshProtocolVersion(%q) = %q, want %q", ident, got, want)
		}
	}
}

func TestReadSSHPacketRejectsOversize(t *testing.T) {
	// A length header claiming more than the max must be rejected, not allocated.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], sshMaxPacket+1)
	r := strings.NewReader(string(hdr[:]))
	if _, ok := readSSHPacket(bufio.NewReader(r)); ok {
		t.Errorf("oversize packet length should be rejected")
	}
}
