package connpool

import (
	"net"
	"testing"
	"time"
)

func TestPoolGetPut(t *testing.T) {

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	p := New(4, 10*time.Second, 2*time.Second)
	defer p.Close()

	conn, err := p.Get(addr)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection")
	}

	p.Put(addr, conn)

	p.mu.Lock()
	idleCount := len(p.idle[addr])
	p.mu.Unlock()
	if idleCount != 1 {
		t.Errorf("expected 1 idle connection, got %d", idleCount)
	}
}

func TestPoolMaxSize(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn
		}
	}()

	maxSize := 2
	p := New(maxSize, 10*time.Second, 2*time.Second)
	defer p.Close()

	var conns []net.Conn
	for i := 0; i < maxSize+1; i++ {
		c, err := p.Get(addr)
		if err != nil {
			t.Fatalf("Get %d failed: %v", i, err)
		}
		conns = append(conns, c)
	}

	for _, c := range conns {
		p.Put(addr, c)
	}

	p.mu.Lock()
	idleCount := len(p.idle[addr])
	p.mu.Unlock()

	if idleCount > maxSize {
		t.Errorf("expected at most %d idle connections, got %d", maxSize, idleCount)
	}
}
