package scan

import "strings"

// A UDP port scan lives or dies on the payload. Most UDP services answer
// only a well-formed request for their own protocol and stay silent for
// anything else -- an empty datagram gets no reply, so the port reads back
// as open|filtered ("no idea") no matter what is really listening. Sending
// the request a real client would send turns that guess into a definite
// open plus, often, a free service identification from the shape of the
// reply.
//
// This mirrors nmap's nmap-payloads idea on a smaller, curated scale: one
// probe per common UDP service, each with the bytes to send and a cheap
// signature to recognise its answer.

// udpProbe is one protocol's UDP request and how to recognise its reply.
type udpProbe struct {
	// Name is the protocol this probe speaks (e.g. "dns", "snmp"). It is
	// reported as the service when Match confirms the reply.
	Name string

	// Payload is the exact datagram to send -- a minimal but valid request
	// for Name's protocol.
	Payload []byte

	// Match reports whether resp looks like a genuine answer to Payload.
	// It guards against a stray datagram or an ICMP-driven read being
	// mistaken for a real protocol reply. A nil Match means any non-empty
	// reply counts (used where the protocol has no cheap, stable marker).
	Match func(resp []byte) bool
}

// udpProbesByPort maps a destination port to the probes to try there, best
// first. A port can carry more than one protocol (500 is IKE for both IKEv1
// and IKEv2), so this is a slice per port rather than a single probe.
var udpProbesByPort = map[int][]udpProbe{
	53:   {dnsProbe},
	123:  {ntpProbe},
	137:  {netbiosNSProbe},
	161:  {snmpProbe},
	500:  {ikeProbe},
	1900: {ssdpProbe},
	5353: {mdnsProbe},
	5060: {sipProbe},
	111:  {rpcProbe},
	69:   {tftpProbe},
}

// probesForPort returns the probes to try against a port, or nil when none
// is known -- the caller then falls back to its previous behaviour.
func probesForPort(port int) []udpProbe {
	return udpProbesByPort[port]
}

// --- individual protocol probes ---------------------------------------

// dnsProbe is a standard query for the root NS record (a query every
// resolver answers), transaction ID 0x1337. A reply carries the same ID in
// its first two bytes and has the QR response bit (0x80 in byte 2) set.
var dnsProbe = udpProbe{
	Name: "dns",
	Payload: []byte{
		0x13, 0x37, // transaction ID
		0x01, 0x00, // flags: standard query, recursion desired
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // root name (empty label)
		0x00, 0x02, // QTYPE = NS
		0x00, 0x01, // QCLASS = IN
	},
	Match: func(resp []byte) bool {
		return len(resp) >= 4 && resp[0] == 0x13 && resp[1] == 0x37 && resp[2]&0x80 != 0
	},
}

// ntpProbe is a mode 3 (client) v3 request; a server answers with mode 4
// (server) or mode 2, i.e. the low three bits of byte 0 are 4 or 2.
var ntpProbe = udpProbe{
	Name:    "ntp",
	Payload: append([]byte{0x1b}, make([]byte, 47)...), // LI=0 VN=3 Mode=3, then 47 zero bytes
	Match: func(resp []byte) bool {
		if len(resp) < 1 {
			return false
		}
		mode := resp[0] & 0x07
		return mode == 4 || mode == 2
	},
}

// snmpProbe is a v2c GetRequest for sysDescr.0 with community "public". A
// reply is another SNMP message, i.e. a valid ASN.1 SEQUENCE (0x30).
var snmpProbe = udpProbe{
	Name: "snmp",
	Payload: []byte{
		0x30, 0x26, // SEQUENCE, len 38
		0x02, 0x01, 0x01, // version = 1 (v2c)
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // community "public"
		0xa0, 0x19, // GetRequest PDU, len 25
		0x02, 0x04, 0x70, 0x69, 0x6e, 0x67, // request ID
		0x02, 0x01, 0x00, // error status
		0x02, 0x01, 0x00, // error index
		0x30, 0x0b, // varbind list
		0x30, 0x09, // varbind
		0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID 1.3.6.1.2.1 (sysDescr area)
		0x05, 0x00, // value = NULL
	},
	Match: func(resp []byte) bool {
		return len(resp) >= 2 && resp[0] == 0x30
	},
}

// netbiosNSProbe is a NetBIOS Name Service "node status" query for the
// wildcard name "*". A reply echoes the transaction ID (0x1337) and sets
// the response flag.
var netbiosNSProbe = udpProbe{
	Name: "netbios-ns",
	Payload: []byte{
		0x13, 0x37, // transaction ID
		0x00, 0x00, // flags: query
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, // name length (32 bytes, half-ASCII encoded)
		// "*" encoded per RFC 1001, padded with 'A' (0x41 -> "CA")
		0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x00,       // name terminator
		0x00, 0x21, // QTYPE = NBSTAT
		0x00, 0x01, // QCLASS = IN
	},
	Match: func(resp []byte) bool {
		return len(resp) >= 4 && resp[0] == 0x13 && resp[1] == 0x37 && resp[2]&0x80 != 0
	},
}

// ikeProbe is a minimal IKEv1 main-mode Security Association proposal. A
// VPN gateway answers with an ISAKMP message echoing the initiator cookie
// in the first eight bytes.
var ikeProbe = udpProbe{
	Name: "ike",
	Payload: []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x01, // initiator cookie
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // responder cookie (zero)
		0x01,                   // next payload = SA
		0x10,                   // version 1.0
		0x02,                   // exchange type = identity protection (main mode)
		0x00,                   // flags
		0x00, 0x00, 0x00, 0x00, // message ID
		0x00, 0x00, 0x00, 0x1c, // length
		0x00, 0x00, 0x00, 0x08, // SA payload (truncated but parseable header)
	},
	Match: func(resp []byte) bool {
		return len(resp) >= 8 && resp[0] == 0xde && resp[1] == 0xad && resp[2] == 0xbe && resp[3] == 0xef
	},
}

// ssdpProbe is an SSDP (UPnP discovery) M-SEARCH. A device answers with an
// HTTP-style "HTTP/1.1 200 OK" status line.
var ssdpProbe = udpProbe{
	Name: "ssdp",
	Payload: []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n"),
	Match: func(resp []byte) bool {
		return strings.HasPrefix(string(resp), "HTTP/1.1")
	},
}

// mdnsProbe is a multicast-DNS query for _services._dns-sd._udp.local, the
// standard service-enumeration question. The reply is a DNS message with
// the response bit set.
var mdnsProbe = udpProbe{
	Name: "mdns",
	Payload: []byte{
		0x00, 0x00, // transaction ID (0 for mDNS)
		0x00, 0x00, // flags
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		0x07, '_', 'd', 'n', 's', '-', 's', 'd',
		0x04, '_', 'u', 'd', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00,       // name terminator
		0x00, 0x0c, // QTYPE = PTR
		0x00, 0x01, // QCLASS = IN
	},
	Match: func(resp []byte) bool {
		return len(resp) >= 4 && resp[2]&0x80 != 0
	},
}

// sipProbe is a SIP OPTIONS request; a SIP server answers with a
// "SIP/2.0" status line.
var sipProbe = udpProbe{
	Name: "sip",
	Payload: []byte("OPTIONS sip:nm SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP nm;branch=z9hG4bKtcpcat\r\n" +
		"From: <sip:nm@nm>;tag=root\r\n" +
		"To: <sip:nm@nm>\r\n" +
		"Call-ID: tcpcat\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Max-Forwards: 70\r\n" +
		"Content-Length: 0\r\n\r\n"),
	Match: func(resp []byte) bool {
		return strings.HasPrefix(string(resp), "SIP/2.0")
	},
}

// rpcProbe is an ONC RPC (portmapper) NULL call to program 100000. A reply
// echoes the transaction ID (0x1337) and marks the message as a REPLY
// (message type 1 at offset 4).
var rpcProbe = udpProbe{
	Name: "rpcbind",
	Payload: []byte{
		0x00, 0x00, 0x13, 0x37, // XID
		0x00, 0x00, 0x00, 0x00, // message type = CALL
		0x00, 0x00, 0x00, 0x02, // RPC version 2
		0x00, 0x01, 0x86, 0xa0, // program 100000 (portmapper)
		0x00, 0x00, 0x00, 0x02, // program version 2
		0x00, 0x00, 0x00, 0x00, // procedure 0 (NULL)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth null
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // verifier null
	},
	Match: func(resp []byte) bool {
		return len(resp) >= 8 && resp[2] == 0x13 && resp[3] == 0x37 &&
			resp[4] == 0 && resp[5] == 0 && resp[6] == 0 && resp[7] == 1
	},
}

// tftpProbe is a TFTP read request for a file unlikely to exist; a TFTP
// server answers with an ERROR packet (opcode 5), which still proves it is
// listening. Opcode is the first two bytes, big-endian.
var tftpProbe = udpProbe{
	Name: "tftp",
	Payload: append(append([]byte{0x00, 0x01}, []byte("tcpcat.probe")...),
		append([]byte{0x00}, append([]byte("octet"), 0x00)...)...),
	Match: func(resp []byte) bool {
		return len(resp) >= 2 && resp[0] == 0x00 && (resp[1] == 0x05 || resp[1] == 0x03)
	},
}
