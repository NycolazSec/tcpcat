//go:build linux

package scan

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// wireU16 returns the int32 immediate that a raw LoadMem of a big-endian
// wire field compares equal to. eBPF's LoadMem is a plain memory load with
// no implicit network-to-host conversion (see asm.HostTo, which exists
// precisely because callers must swap explicitly): on a little-endian host
// the two wire bytes of e.g. ethertype 0x0800 land in a register as 0x0008,
// not 0x0800. Pre-swapping the comparison constant here, once, avoids an
// extra byte-swap instruction at every comparison site.
func wireU16(networkOrder uint16) int32 {
	return int32(networkOrder>>8 | networkOrder<<8)
}

// generateXDPCollection builds the eBPF program tcpcat attaches to the
// scan interface. It redirects a packet into the AF_XDP socket (xsks_map)
// only if it looks like a reply tcpcat itself is waiting on; everything
// else takes XDP_PASS and continues through the kernel's normal stack
// untouched.
//
// This classification is not an optimization -- it is a correctness
// requirement. The interface tcpcat attaches to is very often the same
// bridge/NIC carrying the operator's own SSH session and any other
// services on the box (see the --ebpf startup warning). Earlier versions
// of this program redirected *every* packet on a queue that had any
// AF_XDP socket registered, with no content filtering at all: on a
// single-queue device (the common case for a Linux bridge, which is what
// getInterfaceRXQueueCount falls back to whenever sysfs doesn't expose
// per-queue directories), that is *all* traffic on the interface, for as
// long as the hook is attached -- every SSH packet, every k3s/Flannel/
// Traefik packet, diverted into tcpcat's own userspace ring instead of
// reaching the kernel's TCP/IP stack at all. That reproduces exactly as a
// total network freeze on the host for the scan's duration, not a
// performance issue: it was confirmed as the actual cause of one such
// freeze (SSH cut, k3s pods destabilized) during testing on a shared
// Docker bridge. srcPort is the run's actual configured probe source port
// (see getSrcPort), so the filter tracks whatever the user set via -g.
//
// Only what tcpcat's own reachable RX paths actually consume is matched:
//   - TCP or UDP whose destination port is srcPort or xdpDiscoverySrcPort
//     (SYN-ACK/RST/UDP replies to our own probes).
//   - ICMP type 3 code 3 (port unreachable), used by the UDP scan's
//     closed-port detection.
//
// ARP and ICMP echo-reply are deliberately left unmatched (XDP_PASS
// unconditionally): DiscoverHostsXDP, the only code that consumes either,
// isn't reachable from the CLI today (host discovery runs and completes
// before the XDP engine is even initialized), so redirecting them would
// only add risk -- ARP in particular, since blindly redirecting it would
// just as surely break every *other* host's address resolution on a
// shared segment -- for a code path nothing currently exercises. Revisit
// this if DiscoverHostsXDP is ever wired back in.
//
// IPv4 headers are assumed to carry no options (a 20-byte header): the
// scan replies this needs to see never do. A reply that did would fail
// this program's bounds check and take XDP_PASS -- tcpcat would miss it,
// which is the safe direction to err in, rather than mis-parsing it as
// something else.
func generateXDPCollection(srcPort uint16) (*ebpf.CollectionSpec, error) {
	xskMap := &ebpf.MapSpec{
		Name:       "xsks_map",
		Type:       ebpf.XSKMap,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 64,
	}

	const (
		ethHdrLen  = 14
		ipHdrLen   = 20 // no options
		l4PortsEnd = ethHdrLen + ipHdrLen + 4 // through src+dst port fields
	)

	insns := asm.Instructions{
		// r2 = data, r3 = data_end (struct xdp_md: data@0, data_end@4)
		asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),
		asm.LoadMem(asm.R3, asm.R1, 4, asm.Word),

		// Ethernet header must fit before touching it.
		asm.Mov.Reg(asm.R6, asm.R2),
		asm.Add.Imm(asm.R6, ethHdrLen),
		asm.JGT.Reg(asm.R6, asm.R3, "pass"),

		// Only IPv4 carries anything tcpcat's RX loop understands.
		asm.LoadMem(asm.R4, asm.R2, 12, asm.Half),
		asm.JNE.Imm(asm.R4, wireU16(0x0800), "pass"),

		// IPv4 header (no options) must fit too.
		asm.Mov.Reg(asm.R6, asm.R2),
		asm.Add.Imm(asm.R6, ethHdrLen+ipHdrLen),
		asm.JGT.Reg(asm.R6, asm.R3, "pass"),

		// Dispatch on IP protocol.
		asm.LoadMem(asm.R4, asm.R2, ethHdrLen+9, asm.Byte),
		asm.JEq.Imm(asm.R4, 6, "check_port"),  // TCP
		asm.JEq.Imm(asm.R4, 17, "check_port"), // UDP
		asm.JNE.Imm(asm.R4, 1, "pass"),        // not ICMP either

		// ICMP: only type 3 (dest unreachable) code 3 (port unreachable)
		// is redirected -- the UDP scan's closed-port signal.
		asm.Mov.Reg(asm.R6, asm.R2),
		asm.Add.Imm(asm.R6, ethHdrLen+ipHdrLen+2),
		asm.JGT.Reg(asm.R6, asm.R3, "pass"),
		asm.LoadMem(asm.R4, asm.R2, ethHdrLen+ipHdrLen, asm.Byte),
		asm.JNE.Imm(asm.R4, 3, "pass"),
		asm.LoadMem(asm.R4, asm.R2, ethHdrLen+ipHdrLen+1, asm.Byte),
		asm.JNE.Imm(asm.R4, 3, "pass"),
		asm.Ja.Label("redirect"),

		// TCP/UDP: destination port must be one of ours. Both headers put
		// source port at +0 and destination port at +2.
		asm.Mov.Reg(asm.R6, asm.R2).WithSymbol("check_port"),
		asm.Add.Imm(asm.R6, l4PortsEnd),
		asm.JGT.Reg(asm.R6, asm.R3, "pass"),
		asm.LoadMem(asm.R4, asm.R2, ethHdrLen+ipHdrLen+2, asm.Half),
		asm.JEq.Imm(asm.R4, wireU16(srcPort), "redirect"),
		asm.JNE.Imm(asm.R4, wireU16(xdpDiscoverySrcPort), "pass"),

		// redirect: the packet passed classification -- original
		// queue-lookup-and-redirect logic, unchanged. rx_queue_index
		// (ctx offset 16) is reloaded fresh into r2 here since r1 (ctx)
		// is the only register still guaranteed intact after the
		// classification above.
		asm.LoadMem(asm.R2, asm.R1, 16, asm.Word).WithSymbol("redirect"),
		asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),

		asm.LoadMapPtr(asm.R1, 0).WithReference("xsks_map"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),

		asm.JEq.Imm(asm.R0, 0, "pass"),

		asm.LoadMapPtr(asm.R1, 0).WithReference("xsks_map"),
		asm.LoadMem(asm.R2, asm.RFP, -4, asm.Word),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRedirectMap.Call(),
		asm.Ja.Label("exit"),

		asm.Mov.Imm(asm.R0, 2).WithSymbol("pass"),

		asm.Return().WithSymbol("exit"),
	}

	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"xsks_map": xskMap,
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"tcpcat_xdp_hook": {
				Type:         ebpf.XDP,
				License:      "GPL",
				Instructions: insns,
			},
		},
	}

	return spec, nil
}
