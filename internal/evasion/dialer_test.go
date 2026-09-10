//go:build !windows

package evasion

import (
	"net"
	"syscall"
	"testing"
	"time"
)

// acceptAndDiscard runs a trivial accept loop so CustomDialer.Dial has
// somewhere to connect; it stops when the listener is closed.
func acceptAndDiscard(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

func TestCustomDialerSetsIPv4TTL(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go acceptAndDiscard(ln)

	dialer := NewCustomDialer(&Config{TTL: 42}, 2*time.Second)
	conn, err := dialer.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	ttl, err := getIntSockopt(conn, syscall.IPPROTO_IP, syscall.IP_TTL)
	if err != nil {
		t.Fatalf("GetsockoptInt(IP_TTL) error = %v", err)
	}
	if ttl != 42 {
		t.Errorf("IP_TTL = %d, want 42", ttl)
	}
}

func TestCustomDialerSetsIPv6HopLimit(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("could not bind an IPv6 loopback listener (no IPv6 support on this runner?): %v", err)
	}
	defer func() { _ = ln.Close() }()
	go acceptAndDiscard(ln)

	dialer := NewCustomDialer(&Config{TTL: 42}, 2*time.Second)
	conn, err := dialer.Dial("tcp6", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	// The bug this guards against: setting IP_TTL (the IPv4 sockopt level)
	// on an IPv6 socket silently does nothing, so IPV6_UNICAST_HOPS -- the
	// actual IPv6 hop-limit sockopt -- must be the one that changed.
	hops, err := getIntSockopt(conn, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS)
	if err != nil {
		t.Fatalf("GetsockoptInt(IPV6_UNICAST_HOPS) error = %v", err)
	}
	if hops != 42 {
		t.Errorf("IPV6_UNICAST_HOPS = %d, want 42", hops)
	}
}

func getIntSockopt(conn net.Conn, level, opt int) (int, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, syscall.EINVAL
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}

	var value int
	var getErr error
	if err := raw.Control(func(fd uintptr) {
		value, getErr = syscall.GetsockoptInt(int(fd), level, opt)
	}); err != nil {
		return 0, err
	}
	return value, getErr
}
