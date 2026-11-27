// Command labsrv runs the services of an AI lab target (see test/ailab): one
// listener per -s flag, each behaving like a kind of server a hardened
// machine may expose. It prints "ready" once every listener is bound.
//
//	labsrv -s '22|banner|SSH-2.0-OpenSSH_9.6p1 Debian-5|2s' -s '80|http|nginx/1.24.0' -s '2222|tarpit||1s'
//
// Modes:
//
//	banner  sends the text after the delay, then holds the connection
//	silent  accepts and never says anything
//	http    answers HTTP requests with the text as Server header (/ only)
//	tarpit  sends a random line every delay, forever, never an SSH version
//	        (what endlessh does to keep bots busy)
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

type specs []string

func (s *specs) String() string     { return strings.Join(*s, ", ") }
func (s *specs) Set(v string) error { *s = append(*s, v); return nil }

// hold is how long a connection is kept open at most.
const hold = 60 * time.Second

func main() {
	var ss specs
	addr := flag.String("addr", "0.0.0.0", "Address to listen on")
	flag.Var(&ss, "s", "port|mode|text|delay (repeatable)")
	flag.Parse()
	for _, s := range ss {
		parts := strings.SplitN(s, "|", 4)
		for len(parts) < 4 {
			parts = append(parts, "")
		}
		port, mode, text := parts[0], parts[1], parts[2]
		delay := time.Duration(0)
		if parts[3] != "" {
			d, err := time.ParseDuration(parts[3])
			if err != nil {
				fail(err)
			}
			delay = d
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(*addr, port))
		if err != nil {
			fail(err)
		}
		handler, ok := map[string]func(net.Conn){
			"banner": func(c net.Conn) { sleep(delay); _, _ = io.WriteString(c, text+"\r\n"); drain(c) },
			"silent": drain,
			"http":   func(c net.Conn) { serveHTTP(c, text) },
			"tarpit": func(c net.Conn) { tarpit(c, delay) },
		}[mode]
		if !ok {
			fail(fmt.Errorf("unknown mode %q", mode))
		}
		go serve(ln, handler)
	}
	fmt.Println("ready")
	select {}
}

func serve(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(hold))
			handle(c)
		}()
	}
}

func sleep(d time.Duration) {
	if d > 0 {
		time.Sleep(d)
	}
}

// drain keeps the connection open, reading and ignoring, until the client
// leaves or the hold time ends.
func drain(c net.Conn) { _, _ = io.Copy(io.Discard, c) }

func serveHTTP(c net.Conn, server string) {
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	for {
		h, err := r.ReadString('\n')
		if err != nil || h == "\r\n" || h == "\n" {
			break
		}
	}
	status, body := "404 Not Found", "not found"
	if f := strings.Fields(line); len(f) >= 2 && f[1] == "/" {
		status, body = "200 OK", "<html><head><title>lab</title></head><body>lab</body></html>"
	}
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %s\r\nServer: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, server, len(body), body)
}

func tarpit(c net.Conn, every time.Duration) {
	if every <= 0 {
		every = time.Second
	}
	b := make([]byte, 12)
	for {
		time.Sleep(every)
		_, _ = rand.Read(b)
		if _, err := io.WriteString(c, hex.EncodeToString(b)+"\r\n"); err != nil {
			return
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "labsrv:", err)
	os.Exit(1)
}
