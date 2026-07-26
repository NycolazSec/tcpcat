// internal/scan/xdp_asm.go
package scan

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func generateXDPCollection() (*ebpf.CollectionSpec, error) {
	xskMap := &ebpf.MapSpec{
		Name:       "xsks_map",
		Type:       ebpf.XSKMap,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 64,
	}

	insns := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, 16, asm.Word),

		asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),

		asm.LoadMapPtr(asm.R1, 0).WithReference("xsks_map"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),

		asm.JEq.Imm(asm.R0, 0, "pass_packet"),

		asm.LoadMapPtr(asm.R1, 0).WithReference("xsks_map"),
		asm.LoadMem(asm.R2, asm.RFP, -4, asm.Word),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRedirectMap.Call(),
		asm.Ja.Label("exit"),

		asm.Mov.Imm(asm.R0, 2).WithSymbol("pass_packet"),

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
