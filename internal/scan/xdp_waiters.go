//go:build linux

package scan

import "sync"

// The AF_XDP scan path used to publish every reply into a shared sync.Map
// that each probe goroutine polled on a 5 ms timer. That floored every
// probe's latency at ~5 ms even when the reply came back in 0.2 ms -- so
// against same-subnet hosts, where a SYN-ACK returns in well under a
// millisecond, throughput was capped at roughly 200 probes/sec/goroutine
// by the poll granularity alone, nothing to do with the wire.
//
// This mirrors the event-driven waiter model the raw-socket path already
// uses (rawRxWaiters in raw_tcp.go): each probe registers a channel keyed
// by "ip:port" before it transmits, and the single RX loop delivers the
// reply straight into that channel the instant a matching frame arrives.
// The probe wakes on the reply itself, so its latency is the real RTT and
// a fast local reply completes immediately.

// xdpWaiters maps "ip:port" -> chan xdpResponse for a probe awaiting its
// reply. Registered by the scanning goroutine, read by the RX loop.
var xdpWaiters sync.Map

// registerXDPWaiter installs a buffered (cap 1) channel for key and returns
// it with a cleanup func. It MUST be called before the probe is
// transmitted: a sub-millisecond same-subnet reply can otherwise arrive
// before the waiter exists and be dropped, turning an open port into a
// false timeout -- the exact race the register-before-send order avoids.
func registerXDPWaiter(key string) (<-chan xdpResponse, func()) {
	ch := make(chan xdpResponse, 1)
	xdpWaiters.Store(key, ch)
	return ch, func() { xdpWaiters.Delete(key) }
}

// deliverXDPResult hands a reply to the probe waiting on key, if any. A
// reply with no registered waiter is dropped: the probe already completed
// or timed out, so it is useless to a scanner (and the old code leaked
// exactly these late replies into the shared map forever). The send is
// non-blocking, so the one shared RX loop can never stall on a slow or
// already-satisfied consumer.
func deliverXDPResult(key string, resp xdpResponse) {
	chAny, ok := xdpWaiters.Load(key)
	if !ok {
		return
	}
	ch, ok := chAny.(chan xdpResponse)
	if !ok {
		return
	}
	select {
	case ch <- resp:
	default:
	}
}
