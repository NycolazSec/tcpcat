package service

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"
)

// buildModbusDeviceIDResponse assembles a valid Modbus TCP "Read Device
// Identification" reply carrying VendorName/ProductCode/MajorMinorRevision,
// so the probe can be exercised end to end without real PLC hardware.
func buildModbusDeviceIDResponse(vendor, product, revision string) []byte {
	objects := []struct {
		id  byte
		val string
	}{{0x00, vendor}, {0x01, product}, {0x02, revision}}

	pdu := []byte{0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, byte(len(objects))}
	for _, o := range objects {
		pdu = append(pdu, o.id, byte(len(o.val)))
		pdu = append(pdu, []byte(o.val)...)
	}

	frame := make([]byte, 6)
	binary.BigEndian.PutUint16(frame[0:2], 1) // transaction id
	binary.BigEndian.PutUint16(frame[2:4], 0) // protocol id
	binary.BigEndian.PutUint16(frame[4:6], uint16(1+len(pdu)))
	frame = append(frame, 0x01) // unit id
	frame = append(frame, pdu...)
	return frame
}

// startModbusStub accepts one connection, reads the request, writes response
// (if non-nil), and holds the connection open until stop() is called.
func startModbusStub(t *testing.T, response []byte) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			return
		}
		if response != nil {
			_, _ = conn.Write(response)
		}
		<-done
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { close(done); _ = ln.Close() }
}

func dialStub(t *testing.T, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial stub: %v", err)
	}
	return conn
}

func TestModbusIdentifyParsesDeviceID(t *testing.T) {
	resp := buildModbusDeviceIDResponse("Schneider Electric", "BMXP342020", "2.60")
	port, stop := startModbusStub(t, resp)
	defer stop()

	conn := dialStub(t, port)
	defer func() { _ = conn.Close() }()

	name, version, banner, ok := modbusIdentify(conn, 2*time.Second)
	if !ok {
		t.Fatal("expected the Modbus device-ID probe to succeed")
	}
	if name != "modbus/Schneider Electric" {
		t.Errorf("name = %q, want %q", name, "modbus/Schneider Electric")
	}
	if version != "2.60" {
		t.Errorf("version = %q, want %q", version, "2.60")
	}
	if banner != "Schneider Electric BMXP342020 2.60" {
		t.Errorf("banner = %q", banner)
	}
}

func TestModbusIdentifyHandlesException(t *testing.T) {
	// FC 0x2B | 0x80 = 0xAB: device doesn't support device identification.
	exc := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0xAB, 0x01}
	port, stop := startModbusStub(t, exc)
	defer stop()

	conn := dialStub(t, port)
	defer func() { _ = conn.Close() }()

	if _, _, _, ok := modbusIdentify(conn, 2*time.Second); ok {
		t.Fatal("a Modbus exception reply must not be treated as an identification")
	}
}

func TestProbeOTServiceDispatch(t *testing.T) {
	resp := buildModbusDeviceIDResponse("WAGO", "750-8202", "1.7.3")
	port, stop := startModbusStub(t, resp)
	defer stop()

	// Temporarily register the stub's ephemeral port to exercise the
	// dial-and-dispatch wrapper without needing to bind privileged port 502.
	otIdentifiers[port] = modbusIdentify
	defer delete(otIdentifiers, port)

	name, version, _, ok := probeOTService("127.0.0.1", port, 2*time.Second)
	if !ok || name != "modbus/WAGO" || version != "1.7.3" {
		t.Fatalf("probeOTService dispatch failed: name=%q version=%q ok=%v", name, version, ok)
	}
}

func TestProbeOTServiceSkipsUnregisteredPort(t *testing.T) {
	if _, _, _, ok := probeOTService("127.0.0.1", 65000, 200*time.Millisecond); ok {
		t.Fatal("no probe is registered for port 65000; must return ok=false")
	}
}
