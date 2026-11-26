package service

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(p)
	return h, port
}

// An Apache on a port tcpcat does not expect a web server on (8090 on a real
// Pterodactyl host): it says nothing until asked.
func TestDetectServiceSilentWebServerOnUnusualPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.71 (Debian)")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	ip, port := hostPort(t, srv.Listener.Addr().String())
	info := DetectService(ip, port, 2*time.Second, true, "", false, false)
	if info.Name != "apache" || info.Version != "2.4.71" {
		t.Fatalf("got %+v", info)
	}
}

// A TLS service on a non-TLS port number answers plain HTTP with "Client
// sent an HTTP request to an HTTPS server": follow it over TLS.
func TestDetectServiceFollowsTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	ip, port := hostPort(t, srv.Listener.Addr().String())
	info := DetectService(ip, port, 2*time.Second, true, "", false, false)
	if info.Name != "https" || info.TLS == nil {
		t.Fatalf("got %+v", info)
	}
}

func TestDetectServiceKubernetesAPI(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("{\n  \"kind\": \"Status\",\n  \"apiVersion\": \"v1\",\n  \"metadata\": {},\n  \"status\": \"Failure\",\n  \"message\": \"Unauthorized\",\n  \"code\": 401\n}"))
	}))
	defer srv.Close()
	ip, port := hostPort(t, srv.Listener.Addr().String())
	if info := DetectService(ip, port, 2*time.Second, true, "", false, false); info.Name != "kubernetes-api" {
		t.Fatalf("got %+v", info)
	}
}

// A fake Minecraft server answering the server-list ping.
func TestProbeMinecraft(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		for i := 0; i < 2; i++ { // handshake, then status request
			n, err := readVarInt(r)
			if err != nil {
				return
			}
			if _, err := ioReadFull(r, make([]byte, n)); err != nil {
				return
			}
		}
		doc, _ := json.Marshal(map[string]any{
			"version": map[string]any{"name": "Paper 1.21.4", "protocol": 769},
			"players": map[string]any{"max": 20, "online": 3},
		})
		var body bytes.Buffer
		body.WriteByte(0x00)
		writeVarInt(&body, int32(len(doc)))
		body.Write(doc)
		var out bytes.Buffer
		writeVarInt(&out, int32(body.Len()))
		out.Write(body.Bytes())
		_, _ = c.Write(out.Bytes())
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	info, ok := probeMinecraft(conn, 2*time.Second)
	if !ok || info.Name != "minecraft" || info.Version != "Paper 1.21.4" || info.Banner != "Minecraft Paper 1.21.4, 3/20 players" {
		t.Fatalf("got %+v ok=%v", info, ok)
	}
}

func TestVarIntRoundTrip(t *testing.T) {
	for _, v := range []int32{0, 1, 127, 128, 255, 25565, 2097151, -1} {
		var b bytes.Buffer
		writeVarInt(&b, v)
		got, err := readVarInt(bufio.NewReader(&b))
		if err != nil || int32(got) != v {
			t.Errorf("%d -> %d (%v)", v, got, err)
		}
	}
}
