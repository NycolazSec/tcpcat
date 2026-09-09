package connpool

import (
	"net"
	"sync"
	"time"
)

type idleConn struct {
	conn      net.Conn
	idleSince time.Time
}

type Pool struct {
	mu          sync.Mutex
	idle        map[string][]*idleConn
	maxSize     int
	idleTimeout time.Duration
	dialTimeout time.Duration
	stopCh      chan struct{}
}

func New(maxSize int, idleTimeout, dialTimeout time.Duration) *Pool {
	p := &Pool{
		idle:        make(map[string][]*idleConn),
		maxSize:     maxSize,
		idleTimeout: idleTimeout,
		dialTimeout: dialTimeout,
		stopCh:      make(chan struct{}),
	}
	go p.reaper()
	return p
}

func (p *Pool) Get(addr string) (net.Conn, error) {
	p.mu.Lock()
	conns := p.idle[addr]
	for len(conns) > 0 {
		ic := conns[len(conns)-1]
		conns = conns[:len(conns)-1]
		p.idle[addr] = conns
		p.mu.Unlock()

		_ = ic.conn.SetReadDeadline(time.Now().Add(time.Nanosecond))
		var buf [1]byte
		_, err := ic.conn.Read(buf[:])
		_ = ic.conn.SetReadDeadline(time.Time{})

		if isTimeout(err) {

			return ic.conn, nil
		}

		ic.conn.Close()

		p.mu.Lock()
		conns = p.idle[addr]
	}
	p.mu.Unlock()

	return net.DialTimeout("tcp", addr, p.dialTimeout)
}

func (p *Pool) Put(addr string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.idle[addr]) >= p.maxSize {
		conn.Close()
		return
	}
	p.idle[addr] = append(p.idle[addr], &idleConn{conn: conn, idleSince: time.Now()})
}

func (p *Pool) Close() {
	close(p.stopCh)
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, conns := range p.idle {
		for _, ic := range conns {
			ic.conn.Close()
		}
		delete(p.idle, addr)
	}
}

func (p *Pool) reaper() {
	ticker := time.NewTicker(p.idleTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()
			for addr, conns := range p.idle {
				var live []*idleConn
				for _, ic := range conns {
					if now.Sub(ic.idleSince) < p.idleTimeout {
						live = append(live, ic)
					} else {
						ic.conn.Close()
					}
				}
				if len(live) == 0 {
					delete(p.idle, addr)
				} else {
					p.idle[addr] = live
				}
			}
			p.mu.Unlock()
		}
	}
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}
