package service

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// SSHPostureInfo records the algorithms an SSH server offers in its KEXINIT and
// flags the weak or deprecated ones, the same way the TLS and HTTP posture
// probes do for their protocols. It is a configuration audit, not an exploit:
// offering a weak algorithm is a finding to review, not proof a session will
// use it (a modern client negotiates the strongest mutually-supported one).
type SSHPostureInfo struct {
	ProtocolVersion   string   `json:"protocol_version,omitempty"`
	KexAlgorithms     []string `json:"kex_algorithms,omitempty"`
	HostKeyAlgorithms []string `json:"host_key_algorithms,omitempty"`
	Ciphers           []string `json:"ciphers,omitempty"`
	MACs              []string `json:"macs,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
}

const (
	sshMsgKexInit  = 20
	sshMaxPacket   = 35000 // RFC 4253 §6.1 minimum a conformant impl must accept
	sshReadTimeout = 4 * time.Second
)

// sshPostureFromConn audits an SSH server over a connection whose identification
// line has already been read, so no second connection is opened: SSH servers cap
// concurrent (and rapidly repeated) pre-auth connections per source, and a probe
// on its own socket is frequently dropped. ident is the server's "SSH-..." line;
// leftover is any bytes already read from conn after it (the start of the
// server's KEXINIT, if the banner read ran ahead). It returns nil only when the
// line isn't SSH at all.
func sshPostureFromConn(conn net.Conn, ident string, leftover []byte) *SSHPostureInfo {
	if !strings.HasPrefix(ident, "SSH-") {
		return nil
	}
	info := &SSHPostureInfo{ProtocolVersion: sshProtocolVersion(ident)}
	if strings.HasPrefix(info.ProtocolVersion, "1.") || info.ProtocolVersion == "1" {
		info.Warnings = append(info.Warnings, "legacy SSH protocol 1.x offered (insecure)")
	}

	_ = conn.SetReadDeadline(time.Now().Add(sshReadTimeout))
	// Send our own identification so the server proceeds to key exchange.
	if _, err := conn.Write([]byte("SSH-2.0-tcpcat\r\n")); err != nil {
		return info
	}

	// Read the KEXINIT from any bytes already buffered after the ident line,
	// then from the wire.
	br := bufio.NewReader(io.MultiReader(bytes.NewReader(leftover), conn))
	payload, ok := readSSHPacket(br)
	if !ok || len(payload) == 0 || payload[0] != sshMsgKexInit {
		return info
	}

	parseKexInit(payload, info)
	analyzeSSHPosture(info)
	return info
}

// sshProtocolVersion pulls the protoversion field out of an identification
// string "SSH-<protoversion>-<software>".
func sshProtocolVersion(ident string) string {
	rest := strings.TrimPrefix(ident, "SSH-")
	if i := strings.IndexByte(rest, '-'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// readSSHPacket reads one unencrypted binary packet and returns its payload.
// Pre-key-exchange there is no MAC and no compression, so the layout is just
// length-prefixed payload + padding (RFC 4253 §6).
func readSSHPacket(br *bufio.Reader) ([]byte, bool) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		return nil, false
	}
	packetLen := binary.BigEndian.Uint32(lenBuf[:])
	if packetLen < 2 || packetLen > sshMaxPacket {
		return nil, false
	}
	body := make([]byte, packetLen)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, false
	}
	paddingLen := int(body[0])
	if paddingLen+1 > len(body) {
		return nil, false
	}
	return body[1 : len(body)-paddingLen], true
}

// parseKexInit fills info's algorithm lists from a KEXINIT payload. The layout
// (RFC 4253 §7.1) is: byte(20), 16-byte cookie, then ten name-lists; only the
// four that matter for this audit are kept.
func parseKexInit(payload []byte, info *SSHPostureInfo) {
	c := cursor{buf: payload}
	c.skip(1 + 16) // message id + cookie

	kex, ok1 := c.nameList()
	hostKey, ok2 := c.nameList()
	_, ok3 := c.nameList() // encryption c2s (symmetric with s2c in practice)
	encS2C, ok4 := c.nameList()
	_, ok5 := c.nameList() // mac c2s
	macS2C, ok6 := c.nameList()
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return
	}
	info.KexAlgorithms = kex
	info.HostKeyAlgorithms = hostKey
	info.Ciphers = encS2C
	info.MACs = macS2C
}

type cursor struct {
	buf []byte
	pos int
}

func (c *cursor) skip(n int) {
	c.pos += n
}

// nameList reads a uint32-length-prefixed, comma-separated ASCII name-list.
func (c *cursor) nameList() ([]string, bool) {
	if c.pos+4 > len(c.buf) {
		return nil, false
	}
	n := int(binary.BigEndian.Uint32(c.buf[c.pos : c.pos+4]))
	c.pos += 4
	if n < 0 || c.pos+n > len(c.buf) {
		return nil, false
	}
	s := string(c.buf[c.pos : c.pos+n])
	c.pos += n
	if s == "" {
		return nil, true
	}
	return strings.Split(s, ","), true
}

// analyzeSSHPosture turns the offered algorithm lists into human-readable
// warnings, one per category, naming only the weak entries.
func analyzeSSHPosture(info *SSHPostureInfo) {
	if w := weakOf(info.KexAlgorithms, weakSSHKex); len(w) > 0 {
		info.Warnings = append(info.Warnings, fmt.Sprintf("weak key exchange offered: %s", strings.Join(w, ", ")))
	}
	if w := weakOf(info.HostKeyAlgorithms, weakSSHHostKey); len(w) > 0 {
		info.Warnings = append(info.Warnings, fmt.Sprintf("weak host-key algorithm offered: %s", strings.Join(w, ", ")))
	}
	if w := weakOf(info.Ciphers, weakSSHCipher); len(w) > 0 {
		info.Warnings = append(info.Warnings, fmt.Sprintf("weak cipher offered: %s", strings.Join(w, ", ")))
	}
	if w := weakOf(info.MACs, weakSSHMAC); len(w) > 0 {
		info.Warnings = append(info.Warnings, fmt.Sprintf("weak MAC offered: %s", strings.Join(w, ", ")))
	}
}

func weakOf(names []string, isWeak func(string) bool) []string {
	var out []string
	for _, n := range names {
		if isWeak(n) {
			out = append(out, n)
		}
	}
	return out
}

// base strips an "-etm@openssh.com" / "@openssh.com" suffix so a flag matches
// both the plain and the extended-name forms of an algorithm.
func base(name string) string {
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	return name
}

func weakSSHKex(name string) bool {
	n := base(name)
	return strings.HasSuffix(n, "sha1") || strings.Contains(n, "group1-") ||
		strings.HasPrefix(n, "rsa1024") || strings.HasPrefix(n, "gss-group1")
}

func weakSSHHostKey(name string) bool {
	n := base(name)
	// SHA-2 RSA (rsa-sha2-256/512), ed25519, ecdsa are fine; bare ssh-rsa is a
	// SHA-1 signature and ssh-dss is 1024-bit DSA -- both deprecated.
	return n == "ssh-rsa" || n == "ssh-dss" || strings.HasSuffix(n, "-sha1") ||
		strings.Contains(n, "sign-dss")
}

func weakSSHCipher(name string) bool {
	n := base(name)
	return strings.HasSuffix(n, "-cbc") || strings.HasPrefix(n, "arcfour") ||
		strings.HasPrefix(n, "3des") || strings.HasPrefix(n, "des-") ||
		strings.HasPrefix(n, "blowfish") || strings.HasPrefix(n, "cast128") ||
		strings.HasPrefix(n, "rijndael") || n == "none"
}

func weakSSHMAC(name string) bool {
	n := base(name)
	// hmac-sha2-* and umac-128 are fine; md5, bare/truncated sha1, 64-bit umac
	// and truncated (-96) MACs are not.
	return strings.HasPrefix(n, "hmac-md5") || strings.HasPrefix(n, "hmac-sha1") ||
		strings.HasPrefix(n, "umac-64") || strings.HasSuffix(n, "-96") || n == "none"
}
