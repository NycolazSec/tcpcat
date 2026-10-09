package service

import (
	"net"
	"testing"
	"time"
)

// serveMQTTConnack runs a one-shot fake broker on one end of a pipe: it reads
// the client's CONNECT and replies with a CONNACK carrying returnCode.
func serveMQTTConnack(t *testing.T, server net.Conn, returnCode byte) {
	t.Helper()
	go func() {
		buf := make([]byte, 64)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte{0x20, 0x02, 0x00, returnCode})
		_ = server.Close()
	}()
}

func TestProbeMQTTAccepted(t *testing.T) {
	client, server := net.Pipe()
	serveMQTTConnack(t, server, 0x00) // accepted (anonymous)

	info, ok := probeMQTT(client, time.Second)
	if !ok {
		t.Fatalf("probeMQTT should recognize a CONNACK")
	}
	if info.Name != "mqtt" {
		t.Errorf("name = %q, want mqtt", info.Name)
	}
	found := false
	for _, f := range info.Findings {
		if f == "MQTT broker accepts anonymous connections" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the anonymous-connection finding, got %v", info.Findings)
	}
}

func TestProbeMQTTRefused(t *testing.T) {
	client, server := net.Pipe()
	serveMQTTConnack(t, server, 0x05) // not authorized

	info, ok := probeMQTT(client, time.Second)
	if !ok {
		t.Fatalf("a refused CONNACK still identifies MQTT")
	}
	if len(info.Findings) != 0 {
		t.Errorf("a broker requiring auth should raise no anonymous finding, got %v", info.Findings)
	}
}

func TestProbeMQTTNonMQTT(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		buf := make([]byte, 64)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("HTTP/1.1 400 Bad Request\r\n"))
		_ = server.Close()
	}()

	if _, ok := probeMQTT(client, time.Second); ok {
		t.Errorf("a non-MQTT reply must not be identified as MQTT")
	}
}
