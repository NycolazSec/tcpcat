package service

// JARM active TLS server fingerprinting.
//
// This is a direct, byte-for-byte port of the original JARM reference
// implementation (John Althouse, Andrew Smart, RJ Nunaly, Mike Brady;
// Python port by Caleb Yu; https://github.com/salesforce/jarm,
// BSD-3-Clause) -- not a reinterpretation of the technique. JARM sends 10
// deliberately varied TLS ClientHellos (different TLS versions, cipher
// suite orderings, GREASE, ALPN sets, and extension orderings) and
// fuzzy-hashes the 10 ServerHello responses into a 62-hex-character
// fingerprint. Two servers running identical TLS stack software/config
// produce the same JARM hash regardless of hostname or IP, which is why
// this has to match the reference bit-for-bit: a JARM value that diverges
// from the spec won't match any other JARM implementation's output or any
// public JARM threat-intel feed, making it useless for its actual purpose.
//
// Every cipher/ALPN/GREASE table below was extracted programmatically from
// the reference jarm.py (not retyped by hand) and cross-checked by an
// independent count against the source file. The reference implementation
// was also run live against a real target during development to capture a
// ground-truth hash this port was validated against.
//
// It needs raw TLS record/handshake bytes rather than crypto/tls: JARM's
// entire premise is ClientHellos crypto/tls's client API has no way to
// produce (GREASE-prefixed cipher lists, reversed/half/middle-out cipher
// and extension orderings, deliberately invalid ALPN sets). This writes
// hand-built bytes to a plain net.Conn and parses the raw ServerHello back
// by hand, the same category of work this package's raw scanners already
// do at the IP/TCP layer.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

// JARMInfo is the result of an active JARM TLS fingerprint probe (see the
// package doc comment above). Hash is the 62-hex-character fuzzy hash, or
// 62 zeros when the target answered none of the 10 probes (unreachable,
// not a TLS server, or reset every connection).
type JARMInfo struct {
	Hash string `json:"hash,omitempty"`
}

// jarmZeroHash is what jarm_hash() in the reference returns when all 10
// probes came back empty -- computed rather than hand-counted as a 62-char
// literal, since jarmHash checks for it by exact string comparison.
var jarmZeroHash = strings.Repeat("0", 62)

// jarmProfile mirrors one of the reference's 10 [host, port, version,
// cipher_list, cipher_order, GREASE, ALPN, supported_versions, ext_order]
// tuples, minus host/port (passed separately to buildProbe).
type jarmProfile struct {
	version     string // "TLS_1.3", "TLS_1.2", "TLS_1.1"
	cipherList  string // "ALL" or "NO1.3"
	cipherOrder string // "FORWARD", "REVERSE", "TOP_HALF", "BOTTOM_HALF", "MIDDLE_OUT"
	grease      bool
	alpnMode    string // "APLN" or "RARE_APLN"
	supportMode string // "1.2_SUPPORT", "NO_SUPPORT", "1.3_SUPPORT"
	extOrder    string // "FORWARD" or "REVERSE"
}

// jarmProfiles is the reference's queue = [tls1_2_forward, ...] in the same
// order (order matters: it determines which position in the fuzzy hash
// each probe's cipher+version byte lands in).
var jarmProfiles = [10]jarmProfile{
	{"TLS_1.2", "ALL", "FORWARD", false, "APLN", "1.2_SUPPORT", "REVERSE"},
	{"TLS_1.2", "ALL", "REVERSE", false, "APLN", "1.2_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "TOP_HALF", false, "APLN", "NO_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "BOTTOM_HALF", false, "RARE_APLN", "NO_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "MIDDLE_OUT", true, "RARE_APLN", "NO_SUPPORT", "REVERSE"},
	{"TLS_1.1", "ALL", "FORWARD", false, "APLN", "NO_SUPPORT", "FORWARD"},
	{"TLS_1.3", "ALL", "FORWARD", false, "APLN", "1.3_SUPPORT", "REVERSE"},
	{"TLS_1.3", "ALL", "REVERSE", false, "APLN", "1.3_SUPPORT", "FORWARD"},
	{"TLS_1.3", "NO1.3", "FORWARD", false, "APLN", "1.3_SUPPORT", "FORWARD"},
	{"TLS_1.3", "ALL", "MIDDLE_OUT", true, "APLN", "1.3_SUPPORT", "REVERSE"},
}

// ProbeJARM runs the 10-probe JARM sequence against ip:port and returns the
// resulting fingerprint. hostname is the name the target was originally
// asked for (used as the ClientHello SNI, same convention as probeTLS in
// tls.go), or empty when the target was given as a bare address.
//
// Each probe is its own independent connection (JARM inherently needs 10
// separate handshake attempts, one per ClientHello variant); a probe that
// fails to connect, times out, or gets no usable ServerHello back
// contributes an empty "|||" entry rather than aborting the whole scan --
// so a server that behaves inconsistently across probes (rather than
// uniformly refusing or accepting all 10) still yields a partial, real
// fingerprint instead of being forced to the all-zero hash.
func ProbeJARM(ip string, port int, timeout time.Duration, hostname string) *JARMInfo {
	sniHost := hostname
	if sniHost == "" {
		sniHost = ip
	}
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	// A *rand.Rand scoped to this call (rather than a shared package
	// variable) needs no locking even if multiple targets are probed
	// concurrently by the caller.
	rng := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec G404 -- GREASE/random selection only needs entropy diversity, not unpredictability; matches internal/evasion's existing math/rand convention

	var results [10]string
	for i, p := range jarmProfiles {
		payload := buildProbe(sniHost, p, rng)
		data, ok := sendProbe(address, payload, timeout)
		if !ok {
			results[i] = "|||"
			continue
		}
		results[i] = readServerHello(data)
	}

	return &JARMInfo{Hash: jarmHash(results)}
}

// sendProbe opens its own connection, writes payload, and reads back up to
// 1484 bytes (matches the reference's sock.recv(1484) -- large enough for
// a ServerHello plus certificate-start, never needed in full here).
func sendProbe(address string, payload []byte, timeout time.Duration) ([]byte, bool) {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, false
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, false
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, false
	}

	buf := make([]byte, 1484)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, false
	}
	return buf[:n], true
}

// --- ClientHello construction (ports packet_building/get_ciphers/get_extensions/...) ---

func buildProbe(host string, p jarmProfile, rng *rand.Rand) []byte {
	var recordVersion, helloVersion [2]byte
	switch p.version {
	case "TLS_1.3":
		recordVersion = [2]byte{0x03, 0x01}
		helloVersion = [2]byte{0x03, 0x03}
	case "TLS_1.1":
		recordVersion = [2]byte{0x03, 0x02}
		helloVersion = [2]byte{0x03, 0x02}
	case "TLS_1.2":
		recordVersion = [2]byte{0x03, 0x03}
		helloVersion = [2]byte{0x03, 0x03}
	default: // "TLS_1"
		recordVersion = [2]byte{0x03, 0x01}
		helloVersion = [2]byte{0x03, 0x01}
	}

	var clientHello []byte
	clientHello = append(clientHello, helloVersion[:]...)
	clientHello = append(clientHello, randomBytes(rng, 32)...) // Random
	sessionID := randomBytes(rng, 32)
	clientHello = append(clientHello, byte(len(sessionID)))
	clientHello = append(clientHello, sessionID...)

	cipherChoice := getCiphers(p, rng)
	clientHello = append(clientHello, uint16be(len(cipherChoice))...)
	clientHello = append(clientHello, cipherChoice...)
	clientHello = append(clientHello, 0x01) // compression_methods length
	clientHello = append(clientHello, 0x00) // null compression

	clientHello = append(clientHello, getExtensions(host, p, rng)...)

	handshakeBody := make([]byte, 0, 4+len(clientHello))
	handshakeBody = append(handshakeBody, 0x01) // ClientHello
	handshakeBody = append(handshakeBody, 0x00) // length is a 3-byte
	handshakeBody = append(handshakeBody, uint16be(len(clientHello))...) //   uint24; bodies here always fit in 2 bytes
	handshakeBody = append(handshakeBody, clientHello...)

	payload := make([]byte, 0, 5+len(handshakeBody))
	payload = append(payload, 0x16) // TLS record type: Handshake
	payload = append(payload, recordVersion[:]...)
	payload = append(payload, uint16be(len(handshakeBody))...)
	payload = append(payload, handshakeBody...)
	return payload
}

func getCiphers(p jarmProfile, rng *rand.Rand) []byte {
	var list [][]byte
	if p.cipherList == "ALL" {
		list = append(list, cipherListAll...)
	} else {
		list = append(list, cipherListNo13...)
	}
	if p.cipherOrder != "FORWARD" {
		list = cipherMung(list, p.cipherOrder)
	}
	if p.grease {
		list = append([][]byte{chooseGrease(rng)}, list...)
	}
	var out []byte
	for _, c := range list {
		out = append(out, c...)
	}
	return out
}

// cipherMung ports cipher_mung: REVERSE / TOP_HALF / BOTTOM_HALF /
// MIDDLE_OUT reordering, generic enough to reorder ciphers, ALPNs, and TLS
// version lists alike (exactly as the reference reuses it for all three).
func cipherMung(items [][]byte, mode string) [][]byte {
	n := len(items)
	var output [][]byte
	switch mode {
	case "REVERSE":
		for i := n - 1; i >= 0; i-- {
			output = append(output, items[i])
		}
	case "BOTTOM_HALF":
		if n%2 == 1 {
			output = append(output, items[n/2+1:]...)
		} else {
			output = append(output, items[n/2:]...)
		}
	case "TOP_HALF":
		if n%2 == 1 {
			output = append(output, items[n/2])
		}
		output = append(output, cipherMung(cipherMung(items, "REVERSE"), "BOTTOM_HALF")...)
	case "MIDDLE_OUT":
		middle := n / 2
		if n%2 == 1 {
			output = append(output, items[middle])
			for i := 1; i <= middle; i++ {
				output = append(output, items[middle+i])
				output = append(output, items[middle-i])
			}
		} else {
			for i := 1; i <= middle; i++ {
				output = append(output, items[middle-1+i])
				output = append(output, items[middle-i])
			}
		}
	}
	return output
}

func getExtensions(host string, p jarmProfile, rng *rand.Rand) []byte {
	var all []byte
	grease := false
	if p.grease {
		all = append(all, chooseGrease(rng)...)
		all = append(all, 0x00, 0x00)
		grease = true
	}
	all = append(all, extensionServerName(host)...)
	all = append(all, 0x00, 0x17, 0x00, 0x00) // extended_master_secret
	all = append(all, 0x00, 0x01, 0x00, 0x01, 0x01) // max_fragment_length
	all = append(all, 0xff, 0x01, 0x00, 0x01, 0x00) // renegotiation_info
	all = append(all, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19) // supported_groups
	all = append(all, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00) // ec_point_formats
	all = append(all, 0x00, 0x23, 0x00, 0x00)             // session_ticket
	all = append(all, appLayerProtoNegotiation(p)...)
	all = append(all, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01) // signature_algorithms
	all = append(all, keyShare(grease, rng)...)
	all = append(all, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01) // psk_key_exchange_modes
	if p.version == "TLS_1.3" || p.supportMode == "1.2_SUPPORT" {
		all = append(all, supportedVersions(p, grease, rng)...)
	}
	out := make([]byte, 0, 2+len(all))
	out = append(out, uint16be(len(all))...)
	out = append(out, all...)
	return out
}

func extensionServerName(host string) []byte {
	ext := []byte{0x00, 0x00}
	ext = append(ext, uint16be(len(host)+5)...)
	ext = append(ext, uint16be(len(host)+3)...)
	ext = append(ext, 0x00)
	ext = append(ext, uint16be(len(host))...)
	ext = append(ext, []byte(host)...)
	return ext
}

func appLayerProtoNegotiation(p jarmProfile) []byte {
	var alpns [][]byte
	if p.alpnMode == "RARE_APLN" {
		alpns = append(alpns, alpnRare...)
	} else {
		alpns = append(alpns, alpnAll...)
	}
	if p.extOrder != "FORWARD" {
		alpns = cipherMung(alpns, p.extOrder)
	}
	var all []byte
	for _, a := range alpns {
		all = append(all, a...)
	}
	ext := []byte{0x00, 0x10}
	ext = append(ext, uint16be(len(all)+2)...)
	ext = append(ext, uint16be(len(all))...)
	ext = append(ext, all...)
	return ext
}

func keyShare(grease bool, rng *rand.Rand) []byte {
	var shareExt []byte
	if grease {
		shareExt = append(shareExt, chooseGrease(rng)...)
		shareExt = append(shareExt, 0x00, 0x01, 0x00)
	}
	shareExt = append(shareExt, 0x00, 0x1d) // group: x25519
	shareExt = append(shareExt, 0x00, 0x20) // key_exchange length: 32
	shareExt = append(shareExt, randomBytes(rng, 32)...)
	ext := []byte{0x00, 0x33}
	ext = append(ext, uint16be(len(shareExt)+2)...)
	ext = append(ext, uint16be(len(shareExt))...)
	ext = append(ext, shareExt...)
	return ext
}

func supportedVersions(p jarmProfile, grease bool, rng *rand.Rand) []byte {
	var versions [][]byte
	if p.supportMode == "1.2_SUPPORT" {
		versions = [][]byte{{0x03, 0x01}, {0x03, 0x02}, {0x03, 0x03}}
	} else {
		versions = [][]byte{{0x03, 0x01}, {0x03, 0x02}, {0x03, 0x03}, {0x03, 0x04}}
	}
	if p.extOrder != "FORWARD" {
		versions = cipherMung(versions, p.extOrder)
	}
	var body []byte
	if grease {
		body = append(body, chooseGrease(rng)...)
	}
	for _, v := range versions {
		body = append(body, v...)
	}
	ext := []byte{0x00, 0x2b}
	ext = append(ext, uint16be(len(body)+1)...)
	ext = append(ext, byte(len(body)))
	ext = append(ext, body...)
	return ext
}

func chooseGrease(rng *rand.Rand) []byte {
	return greaseValues[rng.Intn(len(greaseValues))]
}

func randomBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	_, _ = rng.Read(b)
	return b
}

func uint16be(n int) []byte {
	return []byte{byte(n >> 8), byte(n)} // #nosec G115 -- n is always a small, locally-computed payload length here, never attacker-controlled
}

// --- ServerHello parsing (ports read_packet/extract_extension_info/find_extension) ---

// readServerHello returns one probe's "<cipher_hex>|<version_hex>|<alpn>|<ext_type_list>"
// component, or "|||" when data isn't a usable ServerHello (a TLS Alert,
// something too short/malformed to be one, or any other handshake
// message). Bounds are checked explicitly throughout rather than relying
// on a recover(), since data is attacker-controlled network input from
// whatever is listening on the scanned port.
func readServerHello(data []byte) string {
	if len(data) == 0 {
		return "|||"
	}
	if data[0] == 21 { // TLS Alert: the target rejected the ClientHello
		return "|||"
	}
	if len(data) <= 5 || data[0] != 22 || data[5] != 2 { // not a Handshake/ServerHello
		return "|||"
	}
	if len(data) < 46 {
		return "|||"
	}
	serverHelloLength := int(data[3])<<8 | int(data[4])
	counter := int(data[43]) // session_id length
	if counter+46 > len(data) {
		return "|||"
	}
	selectedCipher := data[counter+44 : counter+46]
	version := data[9:11]

	jarm := hex.EncodeToString(selectedCipher) + "|" + hex.EncodeToString(version) + "|"
	jarm += extractExtensionInfo(data, counter, serverHelloLength)
	return jarm
}

func extractExtensionInfo(data []byte, counter, serverHelloLength int) string {
	if counter+53 > len(data) {
		return "|"
	}
	if data[counter+47] == 11 {
		return "|"
	}
	if bytes.Equal(data[counter+50:counter+53], []byte{0x0e, 0xac, 0x0b}) ||
		(len(data) >= 85 && bytes.Equal(data[82:85], []byte{0x0f, 0xf0, 0x0b})) {
		return "|"
	}
	if counter+42 >= serverHelloLength {
		return "|"
	}
	if counter+49 > len(data) {
		return "|"
	}

	count := 49 + counter
	length := int(data[counter+47])<<8 | int(data[counter+48])
	maximum := length + (count - 1)

	var types [][]byte
	var values [][]byte
	for count < maximum {
		if count+4 > len(data) {
			return "|"
		}
		types = append(types, data[count:count+2])
		extLength := int(data[count+2])<<8 | int(data[count+3])
		if extLength == 0 {
			count += 4
			values = append(values, nil)
		} else {
			if count+4+extLength > len(data) {
				return "|"
			}
			values = append(values, data[count+4:count+4+extLength])
			count += extLength + 4
		}
	}

	result := findALPNExtension(types, values)
	result += "|"
	for i, t := range types {
		result += hex.EncodeToString(t)
		if i != len(types)-1 {
			result += "-"
		}
	}
	return result
}

func findALPNExtension(types, values [][]byte) string {
	for i, t := range types {
		if len(t) == 2 && t[0] == 0x00 && t[1] == 0x10 {
			v := values[i]
			if len(v) >= 3 {
				return string(v[3:])
			}
			return ""
		}
	}
	return ""
}

// --- Fuzzy hash (ports jarm_hash/cipher_bytes/version_byte) ---

func jarmHash(results [10]string) string {
	if strings.Join(results[:], ",") == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||" {
		return jarmZeroHash
	}

	var fuzzy strings.Builder
	var alpnsAndExt strings.Builder
	for _, r := range results {
		c := strings.SplitN(r, "|", 4)
		for len(c) < 4 {
			c = append(c, "")
		}
		fuzzy.WriteString(cipherByte(c[0]))
		fuzzy.WriteString(versionByte(c[1]))
		alpnsAndExt.WriteString(c[2])
		alpnsAndExt.WriteString(c[3])
	}
	sum := sha256.Sum256([]byte(alpnsAndExt.String()))
	fuzzy.WriteString(hex.EncodeToString(sum[:])[:32])
	return fuzzy.String()
}

// cipherByte returns the 1-indexed position (2 hex chars, zero-padded) of
// cipher within the canonical cipher-ordering table -- a fuzzy-hash index,
// not the cipher's own wire value. An unrecognized cipher (e.g. a GREASE
// value echoed back abnormally) falls through to len(table)+1, same as the
// reference (no special case for "not found").
func cipherByte(cipher string) string {
	if cipher == "" {
		return "00"
	}
	count := 1
	for _, b := range cipherCanonicalOrder {
		if cipher == hex.EncodeToString(b) {
			break
		}
		count++
	}
	hexValue := fmt.Sprintf("%x", count)
	if len(hexValue) < 2 {
		return "0" + hexValue
	}
	return hexValue
}

// versionByte maps the 4-hex-char wire version (e.g. "0303") to a single
// fuzzy-hash letter. Unlike the reference (which has no bounds guard here
// and would raise on malformed input), this returns "0" for anything that
// doesn't look like a real TLS version byte, since version is built from
// attacker-controlled response bytes.
func versionByte(version string) string {
	if len(version) < 4 {
		return "0"
	}
	options := "abcdef"
	idx := int(version[3] - '0')
	if idx < 0 || idx >= len(options) {
		return "0"
	}
	return string(options[idx])
}

// --- Tables extracted programmatically from the reference jarm.py (see package doc comment) ---

// cipherListAll ports jarm.py's ALL cipher list (get_ciphers, jarm_details[3]=="ALL").
var cipherListAll = [][]byte{
	{0x00, 0x16}, {0x00, 0x33}, {0x00, 0x67}, {0xc0, 0x9e}, {0xc0, 0xa2}, {0x00, 0x9e},
	{0x00, 0x39}, {0x00, 0x6b}, {0xc0, 0x9f}, {0xc0, 0xa3}, {0x00, 0x9f}, {0x00, 0x45},
	{0x00, 0xbe}, {0x00, 0x88}, {0x00, 0xc4}, {0x00, 0x9a}, {0xc0, 0x08}, {0xc0, 0x09},
	{0xc0, 0x23}, {0xc0, 0xac}, {0xc0, 0xae}, {0xc0, 0x2b}, {0xc0, 0x0a}, {0xc0, 0x24},
	{0xc0, 0xad}, {0xc0, 0xaf}, {0xc0, 0x2c}, {0xc0, 0x72}, {0xc0, 0x73}, {0xcc, 0xa9},
	{0x13, 0x02}, {0x13, 0x01}, {0xcc, 0x14}, {0xc0, 0x07}, {0xc0, 0x12}, {0xc0, 0x13},
	{0xc0, 0x27}, {0xc0, 0x2f}, {0xc0, 0x14}, {0xc0, 0x28}, {0xc0, 0x30}, {0xc0, 0x60},
	{0xc0, 0x61}, {0xc0, 0x76}, {0xc0, 0x77}, {0xcc, 0xa8}, {0x13, 0x05}, {0x13, 0x04},
	{0x13, 0x03}, {0xcc, 0x13}, {0xc0, 0x11}, {0x00, 0x0a}, {0x00, 0x2f}, {0x00, 0x3c},
	{0xc0, 0x9c}, {0xc0, 0xa0}, {0x00, 0x9c}, {0x00, 0x35}, {0x00, 0x3d}, {0xc0, 0x9d},
	{0xc0, 0xa1}, {0x00, 0x9d}, {0x00, 0x41}, {0x00, 0xba}, {0x00, 0x84}, {0x00, 0xc0},
	{0x00, 0x07}, {0x00, 0x04}, {0x00, 0x05},
}

// cipherListNo13 ports jarm.py's NO1.3 cipher list.
var cipherListNo13 = [][]byte{
	{0x00, 0x16}, {0x00, 0x33}, {0x00, 0x67}, {0xc0, 0x9e}, {0xc0, 0xa2}, {0x00, 0x9e},
	{0x00, 0x39}, {0x00, 0x6b}, {0xc0, 0x9f}, {0xc0, 0xa3}, {0x00, 0x9f}, {0x00, 0x45},
	{0x00, 0xbe}, {0x00, 0x88}, {0x00, 0xc4}, {0x00, 0x9a}, {0xc0, 0x08}, {0xc0, 0x09},
	{0xc0, 0x23}, {0xc0, 0xac}, {0xc0, 0xae}, {0xc0, 0x2b}, {0xc0, 0x0a}, {0xc0, 0x24},
	{0xc0, 0xad}, {0xc0, 0xaf}, {0xc0, 0x2c}, {0xc0, 0x72}, {0xc0, 0x73}, {0xcc, 0xa9},
	{0xcc, 0x14}, {0xc0, 0x07}, {0xc0, 0x12}, {0xc0, 0x13}, {0xc0, 0x27}, {0xc0, 0x2f},
	{0xc0, 0x14}, {0xc0, 0x28}, {0xc0, 0x30}, {0xc0, 0x60}, {0xc0, 0x61}, {0xc0, 0x76},
	{0xc0, 0x77}, {0xcc, 0xa8}, {0xcc, 0x13}, {0xc0, 0x11}, {0x00, 0x0a}, {0x00, 0x2f},
	{0x00, 0x3c}, {0xc0, 0x9c}, {0xc0, 0xa0}, {0x00, 0x9c}, {0x00, 0x35}, {0x00, 0x3d},
	{0xc0, 0x9d}, {0xc0, 0xa1}, {0x00, 0x9d}, {0x00, 0x41}, {0x00, 0xba}, {0x00, 0x84},
	{0x00, 0xc0}, {0x00, 0x07}, {0x00, 0x04}, {0x00, 0x05},
}

// alpnRare ports jarm.py's RARE_APLN alpns list.
var alpnRare = [][]byte{
	{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39},
	{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30},
	{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31},
	{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32},
	{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33},
	{0x03, 0x68, 0x32, 0x63},
	{0x02, 0x68, 0x71},
}

// alpnAll ports jarm.py's default (APLN) alpns list.
var alpnAll = [][]byte{
	{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39},
	{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30},
	{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31},
	{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31},
	{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32},
	{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33},
	{0x02, 0x68, 0x32},
	{0x03, 0x68, 0x32, 0x63},
	{0x02, 0x68, 0x71},
}

// greaseValues ports jarm.py's choose_grease() grease_list.
var greaseValues = [][]byte{
	{0x0a, 0x0a}, {0x1a, 0x1a}, {0x2a, 0x2a}, {0x3a, 0x3a}, {0x4a, 0x4a}, {0x5a, 0x5a},
	{0x6a, 0x6a}, {0x7a, 0x7a}, {0x8a, 0x8a}, {0x9a, 0x9a}, {0xaa, 0xaa}, {0xba, 0xba},
	{0xca, 0xca}, {0xda, 0xda}, {0xea, 0xea}, {0xfa, 0xfa},
}

// cipherCanonicalOrder ports jarm.py's cipher_bytes() index-lookup list
// (used only by the fuzzy hash -- a different, alphabetized ordering from
// cipherListAll's send order).
var cipherCanonicalOrder = [][]byte{
	{0x00, 0x04}, {0x00, 0x05}, {0x00, 0x07}, {0x00, 0x0a}, {0x00, 0x16}, {0x00, 0x2f},
	{0x00, 0x33}, {0x00, 0x35}, {0x00, 0x39}, {0x00, 0x3c}, {0x00, 0x3d}, {0x00, 0x41},
	{0x00, 0x45}, {0x00, 0x67}, {0x00, 0x6b}, {0x00, 0x84}, {0x00, 0x88}, {0x00, 0x9a},
	{0x00, 0x9c}, {0x00, 0x9d}, {0x00, 0x9e}, {0x00, 0x9f}, {0x00, 0xba}, {0x00, 0xbe},
	{0x00, 0xc0}, {0x00, 0xc4}, {0xc0, 0x07}, {0xc0, 0x08}, {0xc0, 0x09}, {0xc0, 0x0a},
	{0xc0, 0x11}, {0xc0, 0x12}, {0xc0, 0x13}, {0xc0, 0x14}, {0xc0, 0x23}, {0xc0, 0x24},
	{0xc0, 0x27}, {0xc0, 0x28}, {0xc0, 0x2b}, {0xc0, 0x2c}, {0xc0, 0x2f}, {0xc0, 0x30},
	{0xc0, 0x60}, {0xc0, 0x61}, {0xc0, 0x72}, {0xc0, 0x73}, {0xc0, 0x76}, {0xc0, 0x77},
	{0xc0, 0x9c}, {0xc0, 0x9d}, {0xc0, 0x9e}, {0xc0, 0x9f}, {0xc0, 0xa0}, {0xc0, 0xa1},
	{0xc0, 0xa2}, {0xc0, 0xa3}, {0xc0, 0xac}, {0xc0, 0xad}, {0xc0, 0xae}, {0xc0, 0xaf},
	{0xcc, 0x13}, {0xcc, 0x14}, {0xcc, 0xa8}, {0xcc, 0xa9}, {0x13, 0x01}, {0x13, 0x02},
	{0x13, 0x03}, {0x13, 0x04}, {0x13, 0x05},
}
