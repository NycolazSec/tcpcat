package service

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"
)

// Opt-in, read-only identification probes for industrial / OT protocols.
//
// These are only ever run when the operator passes --ot-probe. Unlike the
// passive port-name lookup (resolveDefaultPortName), a probe here speaks the
// device's real protocol to pull an exact vendor/product/version string,
// which is what CVE correlation needs. Two hard rules keep this safe on
// fragile control gear:
//
//   - Every request is a well-formed, standard, READ-ONLY query -- never a
//     malformed packet and never a write/command. A malformed frame is
//     exactly the kind of input that faults a PLC.
//   - One probe per port, then stop. No brute force over unit IDs or object
//     ranges, nothing that hammers a small connection table.
//
// A probe that gets no useful answer returns ok=false and the caller falls
// back to naming the port by number -- the device is no worse off than
// without --ot-probe.

// otIdentifier speaks one OT protocol over an already-dialled connection and
// returns the product name, version, and a human-readable banner. ok is
// false when the device didn't answer with something identifiable.
type otIdentifier func(conn net.Conn, timeout time.Duration) (name, version, banner string, ok bool)

// otIdentifiers maps a TCP port to its identification probe. Only ports
// listed here are ever actively probed under --ot-probe.
var otIdentifiers = map[int]otIdentifier{
	502:   modbusIdentify,
	44818: enipIdentify,
}

// probeOTService dials the port itself (own connection, closed here, same
// discipline as the other probes in this package) and runs the registered
// identifier for that port, if any.
func probeOTService(ip string, port int, timeout time.Duration) (name, version, banner string, ok bool) {
	identify, has := otIdentifiers[port]
	if !has {
		return "", "", "", false
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return "", "", "", false
	}
	defer func() { _ = conn.Close() }()

	return identify(conn, timeout)
}

// modbusIdentify sends a single Modbus "Read Device Identification" request
// (function code 0x2B, MEI type 0x0E, read-device-id 0x01 "basic") and
// parses the VendorName / ProductCode / MajorMinorRevision objects from the
// reply. This is a standard, read-only diagnostic function; it changes
// nothing on the device.
//
// Frame (Modbus TCP): MBAP header {transaction, protocol=0, length, unit}
// followed by the PDU {2B 0E 01 00}. Unit ID 1 addresses a single device
// directly; we deliberately do not sweep other unit IDs.
func modbusIdentify(conn net.Conn, timeout time.Duration) (name, version, banner string, ok bool) {
	req := []byte{
		0x00, 0x01, // transaction id
		0x00, 0x00, // protocol id (always 0 for Modbus)
		0x00, 0x05, // length: unit id + 4-byte PDU
		0x01,             // unit id
		0x2B, 0x0E, 0x01, // FC 43 / MEI 14 / read device id "basic"
		0x00, // object id 0 (start at VendorName)
	}

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return "", "", "", false
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return "", "", "", false
	}
	resp := buf[:n]

	// MBAP: protocol id must be 0; length must match what we actually read.
	if binary.BigEndian.Uint16(resp[2:4]) != 0 {
		return "", "", "", false
	}
	declaredLen := int(binary.BigEndian.Uint16(resp[4:6]))
	if declaredLen < 2 || 6+declaredLen > n {
		return "", "", "", false
	}

	pdu := resp[7:n] // skip 7-byte MBAP header (unit id at resp[6])
	// A Modbus exception reply sets the high bit of the function code
	// (0x2B -> 0xAB): the device simply doesn't support device ID. Not an
	// error on our side -- just nothing to report.
	if len(pdu) < 6 || pdu[0] != 0x2B || pdu[1] != 0x0E {
		return "", "", "", false
	}

	// PDU: FC, MEI, readDeviceIdCode, conformity, moreFollows, nextObjId,
	// numObjects, then repeated {objId, objLen, objValue...}.
	numObjects := int(pdu[6])
	objects := map[byte]string{}
	p := 7
	for i := 0; i < numObjects && p+2 <= len(pdu); i++ {
		objID := pdu[p]
		objLen := int(pdu[p+1])
		p += 2
		if p+objLen > len(pdu) {
			break
		}
		objects[objID] = sanitizeBanner(string(pdu[p : p+objLen]))
		p += objLen
	}

	vendor := objects[0x00]   // VendorName
	product := objects[0x01]  // ProductCode
	revision := objects[0x02] // MajorMinorRevision
	if vendor == "" && product == "" && revision == "" {
		return "", "", "", false
	}

	name = "modbus"
	if vendor != "" {
		// A vendor-qualified name (e.g. "modbus/Schneider Electric") gives
		// CVE correlation a real product string to key on.
		name = "modbus/" + vendor
	}
	bannerParts := []string{}
	for _, part := range []string{vendor, product, revision} {
		if part != "" {
			bannerParts = append(bannerParts, part)
		}
	}
	return name, revision, strings.Join(bannerParts, " "), true
}

// enipIdentify sends an EtherNet/IP "List Identity" request (encapsulation
// command 0x0063) and parses the CIP Identity item from the reply for the
// product name and revision. List Identity is a standard, read-only
// discovery command -- it queries the device's identity object and changes
// nothing. The reply's Product Name (e.g. "1756-L61/B LOGIX5561") plus the
// major.minor revision give CVE correlation a concrete string to key on.
func enipIdentify(conn net.Conn, timeout time.Duration) (name, version, banner string, ok bool) {
	// Encapsulation header (24 bytes), all little-endian: command 0x0063,
	// length 0 (no command data), the rest zero. A zero session handle is
	// valid for List Identity (it needs no registered session).
	req := make([]byte, 24)
	binary.LittleEndian.PutUint16(req[0:2], 0x0063)

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return "", "", "", false
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 24 {
		return "", "", "", false
	}
	resp := buf[:n]

	// Reply must echo command 0x0063 and report status 0 (success).
	if binary.LittleEndian.Uint16(resp[0:2]) != 0x0063 {
		return "", "", "", false
	}
	if binary.LittleEndian.Uint32(resp[8:12]) != 0 {
		return "", "", "", false
	}

	data := resp[24:] // encapsulation data follows the 24-byte header
	// data: item count (2), item type (2), item length (2), then the CIP
	// identity structure.
	if len(data) < 6 {
		return "", "", "", false
	}
	if binary.LittleEndian.Uint16(data[2:4]) != 0x000C { // CIP Identity item
		return "", "", "", false
	}
	id := data[6:]
	// Identity layout up to the fields we read:
	//   protocol version (2), socket address (16), vendor id (2),
	//   device type (2), product code (2), revision major (1) + minor (1),
	//   status (2), serial (4), product name length (1), product name (n).
	const nameLenOff = 2 + 16 + 2 + 2 + 2 + 2 + 2 + 4 // = 32
	if len(id) < nameLenOff+1 {
		return "", "", "", false
	}
	revMajor := id[2+16+2+2+2]
	revMinor := id[2+16+2+2+2+1]
	nameLen := int(id[nameLenOff])
	if nameLen == 0 || nameLenOff+1+nameLen > len(id) {
		return "", "", "", false
	}
	product := sanitizeBanner(string(id[nameLenOff+1 : nameLenOff+1+nameLen]))
	if product == "" {
		return "", "", "", false
	}

	version = strconv.Itoa(int(revMajor)) + "." + strconv.Itoa(int(revMinor))
	return "ethernet-ip", version, product + " " + version, true
}
