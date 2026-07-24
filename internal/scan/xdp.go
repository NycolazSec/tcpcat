// internal/scan/xdp.go
package scan

import (
	"fmt"
	"log"
	"net"
	"time"

	"tcpcat/config"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Global XDP Socket
var GlobalXsk *xdp.Socket
var localMAC net.HardwareAddr
var gatewayMAC net.HardwareAddr
var localIP net.IP // Va stocker la vraie IP de ton VPS (ex: 10.x.x.x)

// getDefaultNetworkInfo simule une connexion sortante pour forcer l'OS à révéler 
// son interface principale (ens3, eth0...) et l'IP associée.
func getDefaultNetworkInfo() (string, net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, err
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(localAddr.IP) {
				return i.Name, ip, nil
			}
		}
	}
	return "", nil, fmt.Errorf("impossible de détecter l'interface par défaut")
}

// InitXDPEngine initialise le moteur eBPF complet automatiquement.
func InitXDPEngine() (*xdp.Socket, error) {
	queueID := 0

	// 💡 DÉTECTION AUTOMATIQUE DU RÉSEAU
	ifaceName, ip, err := getDefaultNetworkInfo()
	if err != nil {
		return nil, fmt.Errorf("erreur de détection réseau: %v", err)
	}
	localIP = ip

	log.Printf("[*] Auto-détection: Interface '%s' sélectionnée (IP source: %s)", ifaceName, localIP.String())

	// =====================================================================
	// ÉTAPE 1 : Génération de l'assembleur et Chargement dans le Noyau
	// =====================================================================
	spec, err := generateXDPCollection()
	if err != nil {
		return nil, fmt.Errorf("erreur de génération de l'assembleur BPF: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("erreur de chargement eBPF dans le noyau: %v", err)
	}

	prog := coll.Programs["tcpcat_xdp_hook"]
	xskMap := coll.Maps["xsks_map"]

	// =====================================================================
	// ÉTAPE 2 : Attachement physique à la carte réseau
	// =====================================================================
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface réseau %s introuvable: %v", ifaceName, err)
	}

	localMAC = iface.HardwareAddr

	_, err = link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return nil, fmt.Errorf("impossible d'attacher le hook XDP: %v", err)
	}
	log.Println("[+] Hook assembleur eBPF attaché au niveau physique avec succès.")

	// =====================================================================
	// ÉTAPE 3 : Création du Socket AF_XDP 
	// =====================================================================
	xsk, err := xdp.NewSocket(iface.Index, queueID, nil)
	if err != nil {
		return nil, fmt.Errorf("échec de la création du socket AF_XDP: %v", err)
	}

	key := uint32(queueID)
	val := uint32(xsk.FD())
	if err := xskMap.Put(&key, &val); err != nil {
		return nil, fmt.Errorf("échec du pontage FD dans xsks_map: %v", err)
	}

	log.Println("[+] Pont Zéro-Copie (Ring Buffer) établi. Moteur prêt à l'emploi.")
	return xsk, nil
}

// ScanXDPPort est appelé par le Worker Pool pour tirer à vitesse maximale
func ScanXDPPort(ip string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	if GlobalXsk == nil {
		return TargetResult{IP: ip, Port: port, State: StateClosed, Reason: "XDP engine offline"}
	}

	targetIP := net.ParseIP(ip)

	// Broadcaste l'adresse MAC (pour l'instant, c'est suffisant pour le réseau local)
	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

	// 💡 Utilise l'IP réelle de ta machine au lieu du 192.168.1.100 en dur !
	rawFrame := constructSYNFrame(localMAC, dstMAC, localIP.To4(), targetIP, uint16(opts.SourcePort), uint16(port))

	descs := GlobalXsk.GetDescs(1) 
	frameLen := len(rawFrame)

	copy(GlobalXsk.GetFrame(descs[0]), rawFrame)
	descs[0].Len = uint32(frameLen)

	GlobalXsk.Transmit(descs)

	return TargetResult{
		IP:     ip,
		Port:   port,
		State:  StateOpen,
		Reason: "SYN Sent via AF_XDP",
	}
}