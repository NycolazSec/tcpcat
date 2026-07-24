// internal/scan/xdp_asm.go
package scan

import (
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/asm"
)

// generateXDPCollection builds the entire eBPF program and its shared memory on the fly.
func generateXDPCollection() (*ebpf.CollectionSpec, error) {
    // 1. Definition of shared memory (Ring Buffer / XSKMAP)
    xskMap := &ebpf.MapSpec{
        Name:       "xsks_map",
        Type:       ebpf.XSKMap, // <-- FIX: XSKMap with correct casing
        KeySize:    4, // uint32 (The network card's queue index)
        ValueSize:  4, // uint32 (The file descriptor of our Go socket)
        MaxEntries: 64, // Supports up to 64 hardware queues
    }

    // 2. Writing the program in pure eBPF assembly
    insns := asm.Instructions{
        // --- STEP 1: Read ctx->rx_queue_index ---
        // R1 contains the pointer to the packet structure (ctx)
        // We read the queue index (offset 16 bytes) and put it in R2
        asm.LoadMem(asm.R2, asm.R1, 16, asm.Word),

        // --- STEP 2: Store the index on the stack ---
        // RFP is the stack frame pointer. We store R2 at the position (Stack - 4 bytes)
        asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),

        // --- STEP 3: Check if tcpcat is listening on this index (bpf_map_lookup_elem) ---
        // R1 = Pointer to our Map
        asm.LoadMapPtr(asm.R1, 0).WithReference("xsks_map"),
        // R2 = Pointer to the key (our index stored on the stack)
        asm.Mov.Reg(asm.R2, asm.RFP),
        asm.Add.Imm(asm.R2, -4),
        // Call the kernel helper function
        asm.FnMapLookupElem.Call(),

        // --- STEP 4: Analyze the result ---
        // If R0 == 0 (socket not found), jump to the "pass_packet" label
        asm.JEq.Imm(asm.R0, 0, "pass_packet"),

        // --- STEP 5: Redirect the packet to tcpcat (bpf_redirect_map) ---
        // R1 = Pointer to our Map
        asm.LoadMapPtr(asm.R1, 0).WithReference("xsks_map"),
        // R2 = The index retrieved directly from the stack
        asm.LoadMem(asm.R2, asm.RFP, -4, asm.Word),
        // R3 = Flags (0)
        asm.Mov.Imm(asm.R3, 0),
        // Call the redirect helper (bpf_redirect_map places the XDP_REDIRECT code in R0)
        asm.FnRedirectMap.Call(),
        // Jump to the end
        asm.Ja.Label("exit"),

        // --- LABEL: pass_packet ---
        // R0 = 2 (XDP_PASS constant: let the Linux kernel handle this packet)
        asm.Mov.Imm(asm.R0, 2).WithSymbol("pass_packet"),

        // --- LABEL: exit ---
        // Return the instruction from R0 (either XDP_PASS or XDP_REDIRECT)
        asm.Return().WithSymbol("exit"),
    }

    // 3. Grouping into a Collection ready to be loaded
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