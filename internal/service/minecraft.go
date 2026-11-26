package service

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// probeMinecraft asks a Minecraft Java server for its status, the way the
// game's server list does ("Server List Ping"): a handshake announcing the
// status state, then a status request. The answer is a JSON document with
// the version and the player count. Nothing is changed on the server and no
// login is attempted.
func probeMinecraft(conn net.Conn, timeout time.Duration) (ServiceInfo, bool) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ServiceInfo{}, false
	}
	host, portStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
	port, _ := strconv.Atoi(portStr)

	var hs bytes.Buffer
	hs.WriteByte(0x00)                 // packet id: handshake
	writeVarInt(&hs, -1)               // protocol version: "any", as status pings send
	writeVarInt(&hs, int32(len(host))) // server address
	hs.WriteString(host)
	_ = binary.Write(&hs, binary.BigEndian, uint16(port))
	writeVarInt(&hs, 1) // next state: status

	var out bytes.Buffer
	writeVarInt(&out, int32(hs.Len()))
	out.Write(hs.Bytes())
	out.Write([]byte{0x01, 0x00}) // status request: length 1, packet id 0
	if _, err := conn.Write(out.Bytes()); err != nil {
		return ServiceInfo{}, false
	}

	r := bufio.NewReader(conn)
	length, err := readVarInt(r)
	if err != nil || length < 3 || length > 1<<20 {
		return ServiceInfo{}, false
	}
	if id, err := readVarInt(r); err != nil || id != 0x00 {
		return ServiceInfo{}, false
	}
	n, err := readVarInt(r)
	if err != nil || n <= 0 || n > length {
		return ServiceInfo{}, false
	}
	doc := make([]byte, n)
	if _, err := ioReadFull(r, doc); err != nil {
		return ServiceInfo{}, false
	}
	var status struct {
		Version struct {
			Name     string `json:"name"`
			Protocol int    `json:"protocol"`
		} `json:"version"`
		Players struct {
			Max    int `json:"max"`
			Online int `json:"online"`
		} `json:"players"`
	}
	if err := json.Unmarshal(doc, &status); err != nil || status.Version.Name == "" {
		return ServiceInfo{}, false
	}
	return ServiceInfo{
		Name:    "minecraft",
		Version: status.Version.Name,
		Banner:  sanitizeBanner(fmt.Sprintf("Minecraft %s, %d/%d players", status.Version.Name, status.Players.Online, status.Players.Max)),
	}, true
}

func writeVarInt(b *bytes.Buffer, v int32) {
	u := uint32(v)
	for {
		if u&^0x7F == 0 {
			b.WriteByte(byte(u))
			return
		}
		b.WriteByte(byte(u&0x7F | 0x80))
		u >>= 7
	}
}

func readVarInt(r *bufio.Reader) (int, error) {
	var v uint32
	for i := 0; i < 5; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		v |= uint32(c&0x7F) << (7 * i)
		if c&0x80 == 0 {
			return int(int32(v)), nil
		}
	}
	return 0, errors.New("varint too long")
}

func ioReadFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := r.Read(b[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
