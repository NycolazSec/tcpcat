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
	"tcpcat/internal/evasion"
	"tcpcat/internal/osdetect"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var GlobalXsk any
var xdpLink link.Link
var localMAC net.HardwareAddr
var gatewayMAC net.HardwareAddr
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
	return net.ParseMAC("ff:ff:ff:ff:ff:ff")
}

func InitXDPEngine() (any, error) {
	if xdpRunning {
		log.Println("[*] Le moteur XDP est déjà initialisé.")
		return GlobalXsk, nil
	}

	queueID := 0

	ifaceName, ip, err := getDefaultNetworkInfo()
	if err != nil {
		return nil, fmt.Errorf("erreur de détection réseau: %v", err)
	}
	localIP = ip

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

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("impossible d'attacher le hook XDP: %v", err)
	}
	xdpLink = l
	log.Println("[+] Hook assembleur eBPF attaché au niveau physique avec succès.")

	xsk, err := xdp.NewSocket(iface.Index, queueID, nil)
	if err != nil {
		l.Close()
		coll.Close()
		return nil, fmt.Errorf("échec de la création du socket AF_XDP: %v", err)
	}

	key := uint32(queueID)
	val := uint32(xsk.FD())
	if err := xskMap.Put(&key, &val); err != nil {
		xsk.Close()
		l.Close()
		coll.Close()
		return nil, fmt.Errorf("échec du pontage FD dans xsks_map: %v", err)
	}

	log.Println("[+] Pont Zéro-Copie (Ring Buffer) établi. Moteur prêt à l'emploi.")

	xdpRunning = true
	go xdpRxLoop()

	return xsk, nil
}

func ShutdownXDPEngine() {
	if !xdpRunning {
		return
	}
	xdpRunning = false
	if xdpLink != nil {
		if err := xdpLink.Close(); err != nil {
			log.Printf("[!] Erreur lors du détachement du hook XDP: %v", err)
		} else {
			log.Println("[-] Hook eBPF XDP détaché avec succès.")
		}
	}
}

func xdpRxLoop() {
	for xdpRunning {
		xsk, ok := GlobalXsk.(*xdp.Socket)
		if !ok || xsk == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		freeFill := xsk.NumFreeFillSlots()
		if freeFill > 0 {
			fillDescs := xsk.GetDescs(freeFill)
			xsk.Fill(fillDescs)
		}

		numRx, _, err := xsk.Poll(50)
		if err != nil || numRx == 0 {
			continue
		}

		rxDescs := xsk.Receive(numRx)
		for _, desc := range rxDescs {
			frame := xsk.GetFrame(desc)
			if len(frame) < 14+20 {
				continue
			}
			if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
				continue
			}

			ipStart := 14
			ipHeaderLen := int(frame[ipStart]&0x0F) * 4
			protocol := frame[ipStart+9]
			srcIP := net.IP(frame[ipStart+12 : ipStart+16])

			switch protocol {
			case 6:
				tcpStart := ipStart + ipHeaderLen
				if len(frame) < tcpStart+14 {
					continue
				}
				pktSrcPort := binary.BigEndian.Uint16(frame[tcpStart : tcpStart+2])
				tcpFlags := frame[tcpStart+13]
				key := fmt.Sprintf("%s:%d", srcIP.String(), pktSrcPort)

				if (tcpFlags & 0x12) == 0x12 {
					osSig := osdetect.GenerateSignature(frame, ipStart, tcpStart)
					xdpResults.Store(key, xdpResponse{state: StateOpen, osSig: osSig})
				} else if (tcpFlags & 0x04) != 0 {
					xdpResults.Store(key, xdpResponse{state: StateClosed})
				}

			case 17:
				udpStart := ipStart + ipHeaderLen
				if len(frame) < udpStart+8 {
					continue
				}
				pktSrcPort := binary.BigEndian.Uint16(frame[udpStart : udpStart+2])
				key := fmt.Sprintf("%s:%d", srcIP.String(), pktSrcPort)
				xdpResults.Store(key, xdpResponse{state: StateOpen})

			case 1:
				icmpStart := ipStart + ipHeaderLen
				if len(frame) < icmpStart+8 {
					continue
				}
				icmpType := frame[icmpStart]
				icmpCode := frame[icmpStart+1]

				if icmpType == 3 && icmpCode == 3 {
					originalIPStart := icmpStart + 8
					if len(frame) < originalIPStart+20+8 {
						continue
					}
					originalIPHdrLen := int(frame[originalIPStart]&0x0F) * 4
					originalUDPStart := originalIPStart + originalIPHdrLen

					originalDstIP := net.IP(frame[originalIPStart+16 : originalIPStart+20])
					originalDstPort := binary.BigEndian.Uint16(frame[originalUDPStart+2 : originalUDPStart+4])

					key := fmt.Sprintf("%s:%d", originalDstIP.String(), originalDstPort)
					xdpResults.Store(key, xdpResponse{state: StateClosed})
				}
			}
		}
	}
}

type xdpResponse struct {
	state string
	osSig string
}

func getSrcPort(opts *config.Options) uint16 {
	if opts != nil && opts.SourcePort > 0 {
		return uint16(opts.SourcePort)
	}
	return 54321
}

func ScanXDPPort(ip string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	xsk, ok := GlobalXsk.(*xdp.Socket)
	if !ok || xsk == nil {
		return TargetResult{IP: ip, Port: port, State: StateClosed, Reason: "XDP engine offline"}
	}

	targetIP := net.ParseIP(ip)
	srcPort := getSrcPort(opts)

	rawFrame := constructSYNFrame(localMAC, gatewayMAC, localIP.To4(), targetIP, srcPort, uint16(port))

	mtu := 0
	if opts != nil {
		mtu = 8
	}
	framesToSend := evasion.FragmentPacket(rawFrame, mtu)

	xdpTxLock.Lock()

	for _, frameBytes := range framesToSend {
		maxRetries := 5
		var descs []xdp.Desc
		for attempt := 0; attempt < maxRetries; attempt++ {
			descs = xsk.GetDescs(1)
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
		copy(xsk.GetFrame(descs[0]), frameBytes)
		descs[0].Len = uint32(frameLen)
		xsk.Transmit(descs)
	}

	xdpTxLock.Unlock()

	key := fmt.Sprintf("%s:%d", targetIP.String(), port)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if val, ok := xdpResults.LoadAndDelete(key); ok {
			resp := val.(xdpResponse)
			state := resp.state
			reason := "SYN-ACK Received (AF_XDP)"

			if state == StateOpen && resp.osSig != "" {
				reason = fmt.Sprintf("SYN-ACK [%s]", resp.osSig)
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

func ScanXDPUDPPort(ip string, port int, opts *config.Options, timeout time.Duration) TargetResult {
	xsk, ok := GlobalXsk.(*xdp.Socket)
	if !ok || xsk == nil {
		return TargetResult{IP: ip, Port: port, State: StateClosed, Reason: "XDP engine offline"}
	}

	targetIP := net.ParseIP(ip)
	srcPort := getSrcPort(opts)

	var payload []byte
	if opts != nil && opts.DataString != "" {
		payload = []byte(opts.DataString)
	}

	rawFrame := constructUDPFrame(localMAC, gatewayMAC, localIP.To4(), targetIP, srcPort, uint16(port), payload)

	xdpTxLock.Lock()
	maxRetries := 5
	var descs []xdp.Desc
	for attempt := 0; attempt < maxRetries; attempt++ {
		descs = xsk.GetDescs(1)
		if len(descs) > 0 {
			break
		}
		time.Sleep(time.Microsecond * 50)
	}

	if len(descs) == 0 {
		xdpTxLock.Unlock()
		return TargetResult{IP: ip, Port: port, State: StateFiltered, Reason: "XDP TX Ring Congestion"}
	}

	copy(xsk.GetFrame(descs[0]), rawFrame)
	descs[0].Len = uint32(len(rawFrame))
	xsk.Transmit(descs)
	xdpTxLock.Unlock()

	key := fmt.Sprintf("%s:%d", targetIP.String(), port)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if val, ok := xdpResults.LoadAndDelete(key); ok {
			resp := val.(xdpResponse)
			state := resp.state
			var reason string

			if state == StateOpen {
				reason = "UDP Response Received (AF_XDP)"
			} else if state == StateClosed {
				reason = "ICMP Port Unreachable (AF_XDP)"
			}
			return TargetResult{IP: ip, Port: port, State: state, Reason: reason}
		}
		time.Sleep(5 * time.Millisecond)
	}

	return TargetResult{
		IP:     ip,
		Port:   port,
		State:  StateOpenFiltered,
		Reason: "No Response (Timeout)",
	}
}
