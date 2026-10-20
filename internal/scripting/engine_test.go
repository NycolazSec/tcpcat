package scripting

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The .wasm fixtures are built from examples/wasm-dissector (the SDK
// template) by testdata/build.sh.

// engineWith loads only the named fixtures, since New loads every .wasm
// under the directory it is given.
func engineWith(t *testing.T, fixtures ...string) *ScriptingEngine {
	t.Helper()
	dir := t.TempDir()
	for _, name := range fixtures {
		data, err := os.ReadFile(filepath.Join("testdata", name+".wasm"))
		if err != nil {
			t.Fatalf("fixture %s: %v (run testdata/build.sh)", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".wasm"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e, err := New(dir, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

// serve starts a TCP server on loopback; handle gets each connection's
// first line (empty if the client sent nothing within 200 ms).
func serve(t *testing.T, handle func(firstLine string, c net.Conn)) (string, int, *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var conns int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&conns, 1)
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				line, _ := bufio.NewReader(c).ReadString('\n')
				handle(line, c)
			}()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, &conns
}

func fakeRedis(line string, c net.Conn) {
	switch {
	case strings.HasPrefix(line, "PING"):
		_, _ = c.Write([]byte("+PONG\r\n"))
	case strings.HasPrefix(line, "INFO"):
		body := "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n"
		_, _ = c.Write([]byte("$" + strconv.Itoa(len(body)) + "\r\n" + body + "\r\n"))
	}
}

func outputOf(results []ScriptExecutionResult, name string) map[string]string {
	for _, r := range results {
		if r.ScriptName == name {
			return r.Output
		}
	}
	return nil
}

func TestDissectorIdentifiesRedisThroughProbe(t *testing.T) {
	ip, port, _ := serve(t, fakeRedis)
	out := outputOf(engineWith(t, "redis").RunAll(ip, port), "redis")
	if out["service"] != "redis" || out["version"] != "7.2.4" || out["auth"] != "none" {
		t.Fatalf("redis dissector output = %v", out)
	}
}

func TestDissectorStaysQuietOnAnotherService(t *testing.T) {
	ip, port, _ := serve(t, func(_ string, c net.Conn) {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	})
	if results := engineWith(t, "redis").RunAll(ip, port); len(results) != 0 {
		t.Fatalf("expected no output for a non-Redis service, got %+v", results)
	}
}

func TestDissectorOnClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // nothing listens there any more
	if results := engineWith(t, "redis").RunAll("127.0.0.1", port); len(results) != 0 {
		t.Fatalf("expected no output when the probe can't connect, got %+v", results)
	}
}

func TestProbeBudgetIsEnforced(t *testing.T) {
	ip, port, conns := serve(t, func(_ string, c net.Conn) { _, _ = c.Write([]byte("hi\n")) })
	out := outputOf(engineWith(t, "budget").RunAll(ip, port), "budget")
	if out["answered"] != "4" {
		t.Fatalf("the fixture tries 6 probes; %s were answered, want maxProbesPerRun=4 (%v)", out["answered"], out)
	}
	if got := atomic.LoadInt32(conns); got != maxProbesPerRun {
		t.Errorf("server saw %d connections, want %d", got, maxProbesPerRun)
	}
}

// The sandbox property: whatever a script does, tcpcat.probe only ever dials
// the host:port being scanned.
func TestProbeOnlyDialsTheScannedPort(t *testing.T) {
	ip, port, _ := serve(t, func(_ string, c net.Conn) { _, _ = c.Write([]byte("hi\n")) })
	e := engineWith(t, "redis", "budget")

	var mu sync.Mutex
	dialed := map[string]int{}
	realDial := e.dial
	e.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		mu.Lock()
		dialed[addr]++
		mu.Unlock()
		return realDial(ctx, addr)
	}

	results := e.RunAll(ip, port)
	want := net.JoinHostPort(ip, strconv.Itoa(port))
	if len(dialed) != 1 || dialed[want] == 0 {
		t.Fatalf("dialed %v, want only %s", dialed, want)
	}
	if out := outputOf(results, "budget"); out["target"] != want {
		t.Errorf("script was told target %q, want %q", out["target"], want)
	}
}
