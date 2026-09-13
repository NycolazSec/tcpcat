//go:build linux

package scan

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestConstructARPRequestFrame(t *testing.T) {
	srcMAC, err := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("192.168.1.20")

	frame := constructARPRequestFrame(srcMAC, srcIP, dstIP)

	if len(frame) != 14+28 {
		t.Fatalf("frame length = %d, want %d", len(frame), 14+28)
	}

	// Ethernet header: broadcast dst, our src, EtherType 0x0806.
	for i, b := range frame[0:6] {
		if b != 0xff {
			t.Errorf("dst MAC byte %d = %#x, want 0xff", i, b)
		}
	}
	if got := net.HardwareAddr(frame[6:12]).String(); got != srcMAC.String() {
		t.Errorf("src MAC = %s, want %s", got, srcMAC.String())
	}
	if etherType := binary.BigEndian.Uint16(frame[12:14]); etherType != 0x0806 {
		t.Errorf("EtherType = %#x, want 0x0806", etherType)
	}

	arpStart := 14
	if hw := binary.BigEndian.Uint16(frame[arpStart : arpStart+2]); hw != 1 {
		t.Errorf("hardware type = %d, want 1 (Ethernet)", hw)
	}
	if proto := binary.BigEndian.Uint16(frame[arpStart+2 : arpStart+4]); proto != 0x0800 {
		t.Errorf("protocol type = %#x, want 0x0800 (IPv4)", proto)
	}
	if frame[arpStart+4] != 6 {
		t.Errorf("hardware address length = %d, want 6", frame[arpStart+4])
	}
	if frame[arpStart+5] != 4 {
		t.Errorf("protocol address length = %d, want 4", frame[arpStart+5])
	}
	if op := binary.BigEndian.Uint16(frame[arpStart+6 : arpStart+8]); op != 1 {
		t.Errorf("operation = %d, want 1 (request)", op)
	}
	if got := net.HardwareAddr(frame[arpStart+8 : arpStart+14]).String(); got != srcMAC.String() {
		t.Errorf("sender hardware address = %s, want %s", got, srcMAC.String())
	}
	if got := net.IP(frame[arpStart+14 : arpStart+18]).String(); got != srcIP.String() {
		t.Errorf("sender protocol address = %s, want %s", got, srcIP.String())
	}
	for i, b := range frame[arpStart+18 : arpStart+24] {
		if b != 0 {
			t.Errorf("target hardware address byte %d = %#x, want 0x00 (unresolved)", i, b)
		}
	}
	if got := net.IP(frame[arpStart+24 : arpStart+28]).String(); got != dstIP.String() {
		t.Errorf("target protocol address = %s, want %s", got, dstIP.String())
	}
}

func TestConstructSYNFrameAdvertisesTCPOptions(t *testing.T) {
	srcMAC, err := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	dstMAC, err := net.ParseMAC("11:22:33:44:55:66")
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}

	frame := constructSYNFrame(srcMAC, dstMAC, net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2}, 40000, 443)

	if len(frame) != synFrameLen {
		t.Fatalf("frame length = %d, want %d", len(frame), synFrameLen)
	}

	ipStart, tcpStart := 14, 34
	if got := binary.BigEndian.Uint16(frame[ipStart+2 : ipStart+4]); got != synIPTotalLen {
		t.Errorf("IP total length = %d, want %d", got, synIPTotalLen)
	}

	// Data offset is the high nibble, in 32-bit words. Without options this
	// was 5 (0x50); the whole point of the fix is that it is now 10.
	if got := frame[tcpStart+12] >> 4; got != synTCPHeaderLen/4 {
		t.Errorf("TCP data offset = %d words, want %d", got, synTCPHeaderLen/4)
	}
	if frame[tcpStart+13] != 0x02 {
		t.Errorf("TCP flags = %#x, want 0x02 (SYN only)", frame[tcpStart+13])
	}

	opts := frame[tcpStart+20 : tcpStart+synTCPHeaderLen]

	// A server can only offer SACK, timestamps or window scaling in its
	// SYN/ACK if the client advertised them first -- which is exactly what
	// OS fingerprinting needs the reply to reveal.
	wantKinds := map[byte]string{2: "MSS", 4: "SACK-permitted", 8: "Timestamps", 3: "Window scale"}
	seen := map[byte]bool{}
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 1 { // NOP
			i++
			continue
		}
		if kind == 0 || i+1 >= len(opts) {
			break
		}
		seen[kind] = true
		i += int(opts[i+1])
	}
	for kind, name := range wantKinds {
		if !seen[kind] {
			t.Errorf("SYN probe does not advertise %s (option kind %d)", name, kind)
		}
	}

	if mss := binary.BigEndian.Uint16(opts[2:4]); mss != 1460 {
		t.Errorf("advertised MSS = %d, want 1460", mss)
	}

	// The timestamp TSval is stamped per-frame rather than left as the zero
	// placeholder baked into synOptions.
	if tsval := binary.BigEndian.Uint32(opts[8:12]); tsval == 0 {
		t.Error("timestamp TSval = 0, want a per-probe value")
	}
}

func TestConstructSYNFrameChecksumCoversOptions(t *testing.T) {
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	srcIP, dstIP := net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2}

	frame := constructSYNFrame(srcMAC, dstMAC, srcIP, dstIP, 40000, 443)
	tcpStart := 34

	// Recomputing over the full 40-byte header including the stored checksum
	// must fold to zero; a checksum that only covered the first 20 bytes
	// would leave every option byte unprotected and fail here.
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], synTCPHeaderLen)

	if got := tcpChecksumCalc(pseudo, frame[tcpStart:tcpStart+synTCPHeaderLen]); got != 0 {
		t.Errorf("recomputed TCP checksum = %#x, want 0 (checksum must cover the options)", got)
	}
}
