// internal/scan/xdp_asm.go
package scan

import (
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/asm"
)

// generateXDPCollection construit l'intégralité du programme eBPF et de sa mémoire partagée à la volée.
func generateXDPCollection() (*ebpf.CollectionSpec, error) {
    // 1. Définition de la mémoire partagée (Ring Buffer / XSKMAP)
    xskMap := &ebpf.MapSpec{
        Name:       "xsks_map",
        Type:       ebpf.XSKMap, // <-- CORRECTION : XSKMap avec la bonne casse
        KeySize:    4, // uint32 (L'index de la file de la carte réseau)
        ValueSize:  4, // uint32 (Le descripteur de fichier de notre socket Go)
        MaxEntries: 64, // Supporte jusqu'à 64 files matérielles
    }

    // 2. Écriture du programme en assembleur eBPF pur
    insns := asm.Instructions{
        // --- ÉTAPE 1 : Lire ctx->rx_queue_index ---
        // R1 contient le pointeur vers la structure du paquet (ctx)
        // On lit l'index de la file (offset 16 octets) et on le met dans R2
        asm.LoadMem(asm.R2, asm.R1, 16, asm.Word),

        // --- ÉTAPE 2 : Stocker l'index sur la pile (Stack) ---
        // RFP est le pointeur de la pile. On stocke R2 à la position (Pile - 4 octets)
        asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),

        // --- ÉTAPE 3 : Vérifier si tcpcat écoute sur cet index (bpf_map_lookup_elem) ---
        // R1 = Pointeur vers notre Map
        asm.LoadMapPtr(asm.R1, 0).WithReference("xsks_map"),
        // R2 = Pointeur vers la clé (notre index stocké sur la pile)
        asm.Mov.Reg(asm.R2, asm.RFP),
        asm.Add.Imm(asm.R2, -4),
        // Appel de la fonction du noyau
        asm.FnMapLookupElem.Call(),

        // --- ÉTAPE 4 : Analyser le résultat ---
        // Si R0 == 0 (socket non trouvé), on saute à l'étiquette "pass_packet"
        asm.JEq.Imm(asm.R0, 0, "pass_packet"),

        // --- ÉTAPE 5 : Rediriger le paquet vers tcpcat (bpf_redirect_map) ---
        // R1 = Pointeur vers notre Map
        asm.LoadMapPtr(asm.R1, 0).WithReference("xsks_map"),
        // R2 = L'index récupéré directement de la pile
        asm.LoadMem(asm.R2, asm.RFP, -4, asm.Word),
        // R3 = Flags (0)
        asm.Mov.Imm(asm.R3, 0),
        // Appel de la redirection (bpf_redirect_map place le code XDP_REDIRECT dans R0)
        asm.FnRedirectMap.Call(),
        // On saute à la fin
        asm.Ja.Label("exit"),

        // --- ÉTIQUETTE : pass_packet ---
        // R0 = 2 (Constante XDP_PASS : on laisse le noyau Linux gérer ce paquet)
        asm.Mov.Imm(asm.R0, 2).WithSymbol("pass_packet"),

        // --- ÉTIQUETTE : exit ---
        // On retourne l'instruction de R0 (soit XDP_PASS, soit XDP_REDIRECT)
        asm.Return().WithSymbol("exit"),
    }

    // 3. Regroupement dans une Collection prête à être injectée
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