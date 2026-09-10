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
