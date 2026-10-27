//go:build linux

package passive

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// generateCollection builds the eBPF program tcpcat attaches to the
// sock/inet_sock_set_state tracepoint, plus the ring buffer it reports through.
//
// The program is written as raw eBPF assembly (no C, no clang) to match the
// rest of tcpcat's eBPF engine and keep the build toolchain-free. It reads the
// tracepoint's sample fields directly -- a classic tracepoint context is
// readable without bpf_probe_read -- at the fixed offsets of
// /sys/kernel/tracing/events/sock/inet_sock_set_state/format:
//
//	offset 16  int    oldstate
//	offset 20  int    newstate
//	offset 24  __u16  sport      (host order)
//	offset 26  __u16  dport      (host order)
//	offset 28  __u16  family
//	offset 32  __u8   saddr[4]
//	offset 36  __u8   daddr[4]
//
// These offsets are stable across modern kernels; a hardening follow-up would
// read them from the format file (or move to a BTF-typed tp_btf program).
//
// In kernel it keeps only what is worth reporting -- IPv4 sockets reaching
// LISTEN or ESTABLISHED -- and writes a fixed 32-byte record (see eventSize)
// to the ring buffer for each. Everything else is dropped with no allocation.
func generateCollection() *ebpf.CollectionSpec {
	events := &ebpf.MapSpec{
		Name:       "tcpcat_flows",
		Type:       ebpf.RingBuf,
		MaxEntries: 1 << 16, // 64 KiB ring; plenty for a passive observer
	}

	insns := asm.Instructions{
		// R6 = ctx (the tracepoint sample pointer), kept across the call.
		asm.Mov.Reg(asm.R6, asm.R1),

		// Only AF_INET for now: family := *(u16*)(ctx+28); drop if != 2.
		asm.LoadMem(asm.R1, asm.R6, 28, asm.Half),
		asm.JNE.Imm(asm.R1, afInet, "skip"),

		// newstate := *(u32*)(ctx+20); keep only LISTEN or ESTABLISHED.
		asm.LoadMem(asm.R7, asm.R6, 20, asm.Word),
		asm.JEq.Imm(asm.R7, tcpEstablished, "emit"),
		asm.JEq.Imm(asm.R7, tcpListen, "emit"),
		asm.Ja.Label("skip"),

		// --- build the 32-byte record on the stack at RFP-32 ---
		// oldstate := *(u32*)(ctx+16)
		asm.LoadMem(asm.R8, asm.R6, 16, asm.Word).WithSymbol("emit"),
		asm.StoreMem(asm.RFP, -32, asm.R8, asm.Word), // oldstate @0
		asm.StoreMem(asm.RFP, -28, asm.R7, asm.Word), // newstate @4
		asm.StoreMem(asm.RFP, -24, asm.R1, asm.Half), // family   @8 (R1 == 2)
		// sport @10 := *(u16*)(ctx+24)
		asm.LoadMem(asm.R2, asm.R6, 24, asm.Half),
		asm.StoreMem(asm.RFP, -22, asm.R2, asm.Half),
		// dport @12 := *(u16*)(ctx+26)
		asm.LoadMem(asm.R3, asm.R6, 26, asm.Half),
		asm.StoreMem(asm.RFP, -20, asm.R3, asm.Half),
		asm.StoreImm(asm.RFP, -18, 0, asm.Half), // pad @14
		// saddr @16 := *(u32*)(ctx+32)
		asm.LoadMem(asm.R4, asm.R6, 32, asm.Word),
		asm.StoreMem(asm.RFP, -16, asm.R4, asm.Word),
		// daddr @20 := *(u32*)(ctx+36)
		asm.LoadMem(asm.R5, asm.R6, 36, asm.Word),
		asm.StoreMem(asm.RFP, -12, asm.R5, asm.Word),
		asm.StoreImm(asm.RFP, -8, 0, asm.Word), // pad @24
		asm.StoreImm(asm.RFP, -4, 0, asm.Word), // pad @28

		// bpf_ringbuf_output(&events, data=RFP-32, size=32, flags=0)
		asm.LoadMapPtr(asm.R1, 0).WithReference("tcpcat_flows"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -32),
		asm.Mov.Imm(asm.R3, eventSize),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
		asm.Ja.Label("exit"),

		// return 0 (tracepoint return value is ignored, but keep it clean)
		asm.Mov.Imm(asm.R0, 0).WithSymbol("skip"),
		asm.Return().WithSymbol("exit"),
	}

	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"tcpcat_flows": events,
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"tcpcat_flow_tp": {
				Type:         ebpf.TracePoint,
				License:      "GPL", // ring buffer + tracepoint helpers require GPL
				Instructions: insns,
			},
		},
	}
}
