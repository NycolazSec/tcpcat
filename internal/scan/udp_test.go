package scan

import (
	"net"
	"testing"
	"time"

	"tcpcat/config"
)

func TestProbesForPortKnownAndUnknown(t *testing.T) {
	if p := probesForPort(53); len(p) != 1 || p[0].Name != "dns" {
		t.Errorf("probesForPort(53) = %+v, want the dns probe", p)
	}
	if p := probesForPort(161); len(p) != 1 || p[0].Name != "snmp" {
		t.Errorf("probesForPort(161) = %+v, want the snmp probe", p)
	}
	if p := probesForPort(9999); p != nil {
		t.Errorf("probesForPort(9999) = %+v, want nil for an unknown port", p)
	}
}

func TestUDPProbeMatchers(t *testing.T) {
	tests := []struct {
		name  string
		probe udpProbe
		reply []byte
		want  bool
	}{
		{"dns response bit set", dnsProbe, []byte{0x13, 0x37, 0x81, 0x80, 0, 0}, true},
		{"dns wrong txid", dnsProbe, []byte{0x00, 0x00, 0x81, 0x80}, false},
		{"dns query bit (not a response)", dnsProbe, []byte{0x13, 0x37, 0x01, 0x00}, false},
		{"ntp server mode", ntpProbe, []byte{0x1c}, true}, // mode 4
		{"ntp client mode (not a reply)", ntpProbe, []byte{0x1b}, false},
		{"snmp sequence", snmpProbe, []byte{0x30, 0x20, 0x02}, true},
		{"snmp not asn.1", snmpProbe, []byte{0x00, 0x01}, false},
		{"ssdp http status", ssdpProbe, []byte("HTTP/1.1 200 OK\r\n"), true},
		{"ssdp junk", ssdpProbe, []byte("garbage"), false},
		{"sip status line", sipProbe, []byte("SIP/2.0 200 OK\r\n"), true},
		{"ike cookie echo", ikeProbe, []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4}, true},
		{"ike no echo", ikeProbe, []byte{0x00, 0x00, 0x00, 0x00, 1, 2, 3, 4}, false},
		{"rpc reply", rpcProbe, []byte{0, 0, 0x13, 0x37, 0, 0, 0, 1}, true},
		{"rpc call (not a reply)", rpcProbe, []byte{0, 0, 0x13, 0x37, 0, 0, 0, 0}, false},
		{"tftp error opcode", tftpProbe, []byte{0x00, 0x05, 0, 0}, true},
		{"tftp data opcode", tftpProbe, []byte{0x00, 0x03, 0, 0}, true},
		{"tftp wrong opcode", tftpProbe, []byte{0x00, 0x01, 0, 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.probe.Match(tt.reply); got != tt.want {
				t.Errorf("%s.Match(%x) = %v, want %v", tt.probe.Name, tt.reply, got, tt.want)
			}
		})
	}
}

// startUDPEcho binds a UDP socket on 127.0.0.1 that replies to every
// datagram with reply, and returns its port.
func startUDPEcho(t *testing.T, reply []byte) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_ = n
			_, _ = conn.WriteToUDP(reply, addr)
		}
	}()

	return conn.LocalAddr().(*net.UDPAddr).Port
}

func TestScanUDPPortOpenOnResponse(t *testing.T) {
	// A server that answers any datagram is a plainly open UDP port. With
	// no known probe for this ephemeral port, an explicit --data-string
	// drives the send.
	port := startUDPEcho(t, []byte("pong"))
	opts := &config.Options{DataString: "ping"}

	res := ScanUDPPort("127.0.0.1", port, opts, time.Second, nil, nil, nil, nil)
	if res.State != StateOpen {
		t.Errorf("State = %q, want OPEN (server replied)", res.State)
	}
}

func TestScanUDPPortIdentifiesProtocolReply(t *testing.T) {
	// A server on the DNS port that returns a DNS-shaped response (matching
	// txid + response bit) should be identified as dns, not just "open".
	// probesForPort(53) supplies the DNS probe, so no --data-string here.
	dnsReply := []byte{0x13, 0x37, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	port := startUDPEcho(t, dnsReply)

	// The probe table keys on port 53; point it at our ephemeral port for
	// the duration of the test so the DNS probe is selected.
	udpProbesByPort[port] = []udpProbe{dnsProbe}
	t.Cleanup(func() { delete(udpProbesByPort, port) })

	res := ScanUDPPort("127.0.0.1", port, &config.Options{}, time.Second, nil, nil, nil, nil)
	if res.State != StateOpen {
		t.Fatalf("State = %q, want OPEN", res.State)
	}
	if res.Service != "dns" {
		t.Errorf("Service = %q, want dns (reply matched the DNS probe)", res.Service)
	}
}
