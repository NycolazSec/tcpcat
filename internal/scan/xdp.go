// internal/scan/xdp.go
package scan

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"tcpcat/config"
	"tcpcat/internal/evasion" // 🥷 NOUVEL IMPORT : Ton module d'évasion
	"tcpcat/internal/osdetect"
	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Global XDP Socket
var GlobalXsk *xdp.Socket
var localMAC net.HardwareAddr
var gatewayMAC net.HardwareAddr // DYNAMIQUE
var localIP net.IP

var xdpTxLock sync.Mutex
var xdpResults sync.Map
var xdpRunning bool

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

// getGatewayMAC lit le cache ARP de Linux pour trouver l'adresse MAC du routeur de ton VPS
func getGatewayMAC(ifaceName string) (net.HardwareAddr, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[5] == ifaceName {
			macAddr := fields[3]
			if macAddr != "00:00:00:00:00:00" {
				return net.ParseMAC(macAddr)
			}
		}
	}
	// Fallback si introuvable
	return net.ParseMAC("ff:ff:ff:ff:ff:ff")
}

func InitXDPEngine() (*xdp.Socket, error) {
	queueID := 0

	ifaceName, ip, err := getDefaultNetworkInfo()
	if err != nil {
		return nil, fmt.Errorf("erreur de détection réseau: %v", err)
	}
	localIP = ip

	// 💡 Lecture dynamique de la MAC du routeur OVH
	mac, err := getGatewayMAC(ifaceName)
	if err == nil {
		gatewayMAC = mac
		log.Printf("[*] Auto-détection: Interface '%s' (IP: %s) | Routeur MAC: %s", ifaceName, localIP.String(), gatewayMAC.String())
	} else {
		gatewayMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
		log.Printf("[*] Auto-détection: Interface '%s' (IP: %s) | Routeur MAC: Introuvable (Broadcast fallback)", ifaceName, localIP.String())
	}

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

	xdpRunning = true
	go xdpRxLoop()

	return xsk, nil
}

func xdpRxLoop() {
	for xdpRunning {
		if GlobalXsk == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		freeFill := GlobalXsk.NumFreeFillSlots()
		if freeFill > 0 {
			fillDescs := GlobalXsk.GetDescs(freeFill)
			GlobalXsk.Fill(fillDescs)
		}

		numRx, _, err := GlobalXsk.Poll(50)
		if err != nil || numRx == 0 {
			continue
		}

		rxDescs := GlobalXsk.Receive(numRx)
		for _, desc := range rxDescs {
			frame := GlobalXsk.GetFrame(desc)
			if len(frame) < 54 {
				continue
			}
			if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
				continue
			}

			ipHeaderLen := int(frame[14]&0x0F) * 4
			if frame[14+9] != 6 {
				continue
			}

			tcpStart := 14 + ipHeaderLen
			if len(frame) < tcpStart+20 {
				continue
			}

			ipStart := 14
			srcIPBytes := frame[ipStart+12 : ipStart+16]
			pktSrcPort := binary.BigEndian.Uint16(frame[tcpStart : tcpStart+2])
			tcpFlags := frame[tcpStart+13]

			key := fmt.Sprintf("%s:%d", net.IP(srcIPBytes).String(), pktSrcPort)

			if (tcpFlags & 0x12) == 0x12 { // SYN-ACK = Port Ouvert
				// 🕵️ ON CALCULE LA SIGNATURE ICI !
				osSig := osdetect.GenerateSignature(frame, ipStart, tcpStart)
				
				// On stocke l'état ET la signature, séparés par un pipe "|"
				val := fmt.Sprintf("%s|%s", StateOpen, osSig)
				xdpResults.Store(key, val)
				
			} else if (tcpFlags & 0x04) != 0 { // RST = Port Fermé
				xdpResults.Store(key, StateClosed)
			}
		}
	}
}

func ScanXDPPort(ip string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	if GlobalXsk == nil {
		return TargetResult{IP: ip, Port: port, State: StateClosed, Reason: "XDP engine offline"}
	}

	targetIP := net.ParseIP(ip)
	
	rawFrame := constructSYNFrame(localMAC, gatewayMAC, localIP.To4(), targetIP, uint16(opts.SourcePort), uint16(port))

	// 🥷 ÉVASION : Fragmentation IP si l'option est activée
	mtu := 0
	if opts != nil && opts.Fragment {
		mtu = 8 // Découpage de l'en-tête TCP en blocs minuscules de 8 octets
	}
	framesToSend := evasion.FragmentPacket(rawFrame, mtu)

	// 🔒 DÉBUT DE LA ZONE CRITIQUE TX (Un worker à la fois)
	xdpTxLock.Lock()
	
	// On envoie tous les fragments générés un par un sur le câble
	for _, frameBytes := range framesToSend {
		maxRetries := 5
		var descs []xdp.Desc
		for attempt := 0; attempt < maxRetries; attempt++ {
			descs = GlobalXsk.GetDescs(1)
			if len(descs) > 0 {
				break
			}
			time.Sleep(time.Microsecond * 50)
		}

		if len(descs) == 0 {
			xdpTxLock.Unlock()
			return TargetResult{
				IP:     ip,
				Port:   port,
				State:  StateFiltered,
				Reason: "XDP TX Ring Congestion (Fragment dropped)",
			}
		}

		frameLen := len(frameBytes)
		copy(GlobalXsk.GetFrame(descs[0]), frameBytes)
		descs[0].Len = uint32(frameLen)
		GlobalXsk.Transmit(descs)
	}
	
	xdpTxLock.Unlock()
	// 🔓 FIN DE LA ZONE CRITIQUE TX

	// Lecture de la réponse dans la boîte aux lettres asynchrone
	key := fmt.Sprintf("%s:%d", targetIP.String(), port)
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		if val, ok := xdpResults.LoadAndDelete(key); ok {
			valStr := val.(string)
			state := valStr
			reason := "SYN-ACK Received (AF_XDP)"
			
			// Si on a concaténé l'OS (séparé par un |), on le sépare
			if strings.Contains(valStr, "|") {
				parts := strings.Split(valStr, "|")
				state = parts[0]
				reason = fmt.Sprintf("SYN-ACK [%s]", parts[1])
			} else if state == StateClosed {
				reason = "RST Received (AF_XDP)"
			}
			return TargetResult{IP: ip, Port: port, State: state, Reason: reason}
		}
		time.Sleep(5 * time.Millisecond)
	}

	return TargetResult{
		IP:     ip,
		Port:   port,
		State:  StateFiltered,
		Reason: "No Response (Timeout)",
	}

}