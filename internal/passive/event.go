// Package passive discovers a host's network footprint by *observing* it
// rather than probing it: an eBPF tracepoint on the kernel's TCP state machine
// records every socket that starts listening and every connection that reaches
// ESTABLISHED, so tcpcat can map "what listens here and who talks to whom"
// without sending a single packet. It complements the active scanner and the
// /proc-based `inventory` snapshot with a continuous, traffic-driven view.
//
// This file holds the parts that are portable (types, record decoding); the
// eBPF program and its loader live in the linux-only files.
package passive

import (
	"encoding/binary"
	"fmt"
	"net"
)

// TCP states, from include/net/tcp_states.h. The eBPF program reports the
// transition's old and new state so userspace can tell an inbound connection
// (SYN_RECV -> ESTABLISHED) from an outbound one (SYN_SENT -> ESTABLISHED).
const (
	tcpEstablished = 1
	tcpSynSent     = 2
	tcpSynRecv     = 3
	tcpListen      = 10
)

// afInet is AF_INET. The kernel side filters to IPv4 for now; IPv6 (AF_INET6,
// 10) is a planned follow-up and is simply not emitted yet.
const afInet = 2

// eventSize is the byte size of the fixed record the eBPF program writes to the
// ring buffer. It must stay in lockstep with the asm stores in prog_linux.go.
//
//	offset  field
//	0  u32  oldstate
//	4  u32  newstate
//	8  u16  family
//	10 u16  sport      (host order)
//	12 u16  dport      (host order)
//	14 u16  pad
//	16 [4]  saddr      (network-order bytes)
//	20 [4]  daddr      (network-order bytes)
//	24 u32  pad
//	28 u32  pad
const eventSize = 32

// event is one decoded ring-buffer record.
type event struct {
	OldState uint32
	NewState uint32
	Family   uint16
	SPort    uint16
	DPort    uint16
	SAddr    net.IP
	DAddr    net.IP
}

// decodeEvent parses a raw ring-buffer sample. The integer fields are native
// (little-endian on the hosts tcpcat targets); the addresses are raw bytes in
// network order, exactly as net.IP wants them.
func decodeEvent(b []byte) (event, error) {
	if len(b) < eventSize {
		return event{}, fmt.Errorf("short event: %d bytes", len(b))
	}
	return event{
		OldState: binary.LittleEndian.Uint32(b[0:4]),
		NewState: binary.LittleEndian.Uint32(b[4:8]),
		Family:   binary.LittleEndian.Uint16(b[8:10]),
		SPort:    binary.LittleEndian.Uint16(b[10:12]),
		DPort:    binary.LittleEndian.Uint16(b[12:14]),
		SAddr:    net.IP(append([]byte(nil), b[16:20]...)),
		DAddr:    net.IP(append([]byte(nil), b[20:24]...)),
	}, nil
}

// Flow is an aggregated passive observation.
type Flow struct {
	// Kind is "listen" (a local socket began LISTENing) or "connection".
	Kind string `json:"kind"`
	// Direction is "inbound" or "outbound" for a connection, empty for listen.
	Direction string `json:"direction,omitempty"`

	LocalIP    string `json:"local_ip,omitempty"`
	LocalPort  uint16 `json:"local_port,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`

	// Count is how many times this exact relationship was observed.
	Count int `json:"count"`
}

// key is the dedup/aggregation key for a Flow.
type key struct {
	kind, dir             string
	localIP, remoteIP     string
	localPort, remotePort uint16
}

// classify turns a raw event into an aggregation key, or ok=false to drop it.
// For both connection directions the socket's own address (saddr:sport) is the
// local end and the peer (daddr:dport) is the remote end; only who *initiated*
// differs, which the old state tells us.
func classify(e event) (key, bool) {
	switch e.NewState {
	case tcpListen:
		return key{
			kind:      "listen",
			localIP:   e.SAddr.String(),
			localPort: e.SPort,
		}, true
	case tcpEstablished:
		dir := "outbound"
		if e.OldState == tcpSynRecv {
			dir = "inbound"
		}
		return key{
			kind:       "connection",
			dir:        dir,
			localIP:    e.SAddr.String(),
			localPort:  e.SPort,
			remoteIP:   e.DAddr.String(),
			remotePort: e.DPort,
		}, true
	}
	return key{}, false
}

func (k key) toFlow(count int) Flow {
	return Flow{
		Kind:       k.kind,
		Direction:  k.dir,
		LocalIP:    k.localIP,
		LocalPort:  k.localPort,
		RemoteIP:   k.remoteIP,
		RemotePort: k.remotePort,
		Count:      count,
	}
}
