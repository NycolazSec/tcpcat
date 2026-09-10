//go:build linux

package scan

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
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
var localSubnet *net.IPNet // the interface's own network, for deciding when ARP (rather than routing through the gateway) can reach a discovery target directly

var xdpTxLock sync.Mutex
var xdpResults sync.Map
var xdpDiscovery sync.Map // IP string -> true, populated by xdpRxLoop for host discovery
var xdpRunning bool
var xdpSockets []*xdp.Socket // one per bound RX queue; xdpSockets[0] is also GlobalXsk, the sole TX path

// getInterfaceRXQueueCount reads the number of RX queues an interface
// exposes from sysfs. A NIC with RSS enabled spreads inbound traffic
// across several hardware queues by flow hash, so an AF_XDP socket bound
// to queue 0 alone only ever sees whichever fraction of replies happens to
// hash there -- the rest are invisible to user space, not merely dropped
// after arriving. Falls back to 1 (today's single-queue behavior) if the
// count can't be determined, e.g. inside a container or on a NIC that
// doesn't expose per-queue sysfs entries at all.
func getInterfaceRXQueueCount(ifaceName string) int {
	return countRXQueueDirs(filepath.Join("/sys/class/net", ifaceName, "queues"))
}

// countRXQueueDirs counts "rx-*" entries under a network interface's sysfs
// queues directory, split out from getInterfaceRXQueueCount so it can be
// unit-tested against a fake directory tree instead of the real sysfs path.
func countRXQueueDirs(queuesDir string) int {
	entries, err := os.ReadDir(queuesDir)
	if err != nil {
		return 1
	}
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rx-") {
			count++
		}
	}
	if count < 1 {
		return 1
	}
	return count
}

func getDefaultNetworkInfo() (string, net.IP, *net.IPNet, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", nil, nil, err
	}
	defer func() { _ = conn.Close() }()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, nil, err
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			var ipNet *net.IPNet
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				ipNet = v
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(localAddr.IP) {
				return i.Name, ip, ipNet, nil
			}
		}
	}
	return "", nil, nil, fmt.Errorf("failed to detect default network interface")
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
		log.Println("[*] XDP engine already initialized.")
		return GlobalXsk, nil
	}

	ifaceName, ip, ipNet, err := getDefaultNetworkInfo()
	if err != nil {
		return nil, fmt.Errorf("network interface detection error: %v", err)
	}
	localIP = ip
	localSubnet = ipNet

	mac, err := getGatewayMAC(ifaceName)
	if err == nil {
		gatewayMAC = mac
		log.Printf("[*] Auto-detection: Interface '%s' (IP: %s) | Gateway MAC: %s", ifaceName, localIP.String(), gatewayMAC.String())
	} else {
		gatewayMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
		log.Printf("[*] Auto-detection: Interface '%s' (IP: %s) | Gateway MAC: Not found (broadcast fallback)", ifaceName, localIP.String())
	}

	spec, err := generateXDPCollection()
	if err != nil {
		return nil, fmt.Errorf("eBPF assembly generation error: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("eBPF kernel load error: %v", err)
	}

	prog := coll.Programs["tcpcat_xdp_hook"]
	xskMap := coll.Maps["xsks_map"]

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("network interface %s not found: %v", ifaceName, err)
	}
	localMAC = iface.HardwareAddr

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to attach XDP hook: %v", err)
	}
	xdpLink = l
	log.Println("[+] eBPF assembly hook attached successfully at physical level.")

	numQueues := getInterfaceRXQueueCount(ifaceName)

	xdpSockets = make([]*xdp.Socket, 0, numQueues)
	for q := 0; q < numQueues; q++ {
		xsk, err := xdp.NewSocket(iface.Index, q, nil)
		if err != nil {
			if q == 0 {
				_ = l.Close()
				coll.Close()
				return nil, fmt.Errorf("failed to create AF_XDP socket: %v", err)
			}
			// Queue 0 (required) is already up; sysfs can overstate how many
			// queues actually support their own AF_XDP socket (e.g. some
			// virtual NICs), so just scan with fewer queues than expected
			// rather than failing the whole engine over an extra one.
			log.Printf("[!] Could not bind AF_XDP socket to queue %d (%v); continuing with %d queue(s)", q, err, len(xdpSockets))
			break
		}

		key := uint32(q)
		val := uint32(xsk.FD())
		if err := xskMap.Put(&key, &val); err != nil {
			_ = xsk.Close()
			if q == 0 {
				_ = l.Close()
				coll.Close()
				return nil, fmt.Errorf("échec du pontage FD dans xsks_map: %v", err)
			}
			log.Printf("[!] Could not map AF_XDP socket for queue %d into xsks_map (%v); continuing with %d queue(s)", q, err, len(xdpSockets))
			break
		}

		xdpSockets = append(xdpSockets, xsk)
	}

	log.Printf("[+] Pont Zéro-Copie (Ring Buffer) établi sur %d file(s) RX. Moteur prêt à l'emploi.", len(xdpSockets))

	xdpRunning = true
	for _, xsk := range xdpSockets {
		go xdpRxLoop(xsk)
	}

	return xdpSockets[0], nil
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
	for _, xsk := range xdpSockets {
		_ = xsk.Close()
	}
	xdpSockets = nil
}

// xdpRxLoop drains one AF_XDP socket's RX ring. On a multi-queue NIC,
// InitXDPEngine starts one of these per queue (each bound to its own
// xsks_map slot) since a NIC's RSS hashing can steer replies to any queue,
// not just the one the scan's own probes happen to transmit from; all of
// them feed the same shared xdpResults/xdpDiscovery maps.
func xdpRxLoop(xsk *xdp.Socket) {
	for xdpRunning {
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
			if len(frame) < 14 {
				continue
			}
			etherType := binary.BigEndian.Uint16(frame[12:14])

			if etherType == 0x0806 { // ARP
				if len(frame) < 14+28 {
					continue
				}
				arpStart := 14
				op := binary.BigEndian.Uint16(frame[arpStart+6 : arpStart+8])
				if op == 2 { // reply
					senderIP := net.IP(frame[arpStart+14 : arpStart+18])
					xdpDiscovery.Store(senderIP.String(), true)
				}
				continue
			}

			if etherType != 0x0800 || len(frame) < 14+20 {
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

				xdpDiscovery.Store(srcIP.String(), true) // any TCP reply proves the host is alive

				if (tcpFlags & 0x12) == 0x12 {
					osSig := osdetect.GenerateSignature(frame, ipStart, tcpStart)
					osName, osConfidence := osdetect.ClassifyOS(frame, ipStart, tcpStart)
					xdpResults.Store(key, xdpResponse{
						state:        StateOpen,
						osSig:        osSig,
						osName:       osName,
						osConfidence: osConfidence,
					})

					ourIP := net.IP(frame[ipStart+16 : ipStart+20])
					ourPort := binary.BigEndian.Uint16(frame[tcpStart+2 : tcpStart+4])
					ackSeq := binary.BigEndian.Uint32(frame[tcpStart+8 : tcpStart+12])
					sendRST(xsk, ourIP, srcIP, ourPort, pktSrcPort, ackSeq)
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

				if icmpType == 0 { // Echo Reply: host is alive
					xdpDiscovery.Store(srcIP.String(), true)
				} else if icmpType == 3 && icmpCode == 3 {
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
	state        string
	osSig        string
	osName       string
	osConfidence float64
}

// sendRST closes out the half-open connection a SYN scan leaves behind
// after a SYN/ACK, instead of letting it linger in the target's backlog
// until its own retransmit timer expires. srcIP/srcPort/dstIP/dstPort are
// named from the RST's own point of view (srcIP is ours, dstIP is the
// target that just replied).
func sendRST(xsk *xdp.Socket, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32) {
	if xsk == nil {
		return
	}
	frame := constructRSTFrame(localMAC, gatewayMAC, srcIP, dstIP, srcPort, dstPort, seq)

	xdpTxLock.Lock()
	defer xdpTxLock.Unlock()

	descs := xsk.GetDescs(1)
	if len(descs) == 0 {
		return // TX ring is momentarily full; the target's own SYN/ACK retransmit will get a fresh chance
	}
	copy(xsk.GetFrame(descs[0]), frame)
	descs[0].Len = uint32(len(frame))
	xsk.Transmit(descs)
}

func getSrcPort(opts *config.Options) uint16 {
	if opts != nil && opts.SourcePort > 0 {
		return uint16(opts.SourcePort)
	}
	return 54321
}

// transmitXDPFrames sends each frame in order, waiting briefly for TX ring
// space if it's momentarily full. Returns false (without sending the
// remaining frames) if a slot never frees up, which the caller reports as
// TX congestion rather than silently dropping the probe.
func transmitXDPFrames(xsk *xdp.Socket, frames [][]byte) bool {
	xdpTxLock.Lock()
	defer xdpTxLock.Unlock()

	for _, frameBytes := range frames {
		const maxRetries = 5
		var descs []xdp.Desc
		for attempt := 0; attempt < maxRetries; attempt++ {
			descs = xsk.GetDescs(1)
			if len(descs) > 0 {
				break
			}
			time.Sleep(time.Microsecond * 50)
		}
		if len(descs) == 0 {
			return false
		}

		copy(xsk.GetFrame(descs[0]), frameBytes)
		descs[0].Len = uint32(len(frameBytes))
		xsk.Transmit(descs)
	}
	return true
}

func ScanXDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, rtt *RTTEstimator) TargetResult {
	xsk, ok := GlobalXsk.(*xdp.Socket)
	if !ok || xsk == nil {
		return TargetResult{IP: ip, Port: port, State: StateClosed, Reason: "XDP engine offline"}
	}

	if opts != nil && opts.DecoyIPs != "" {
		decoys, err := evasion.ParseDecoys(opts.DecoyIPs)
		if err == nil {
			targetIP := net.ParseIP(ip)
			srcPort := getSrcPort(opts)
			for _, decoyIP := range decoys {
				go func(decoyIP net.IP) {
					frame := constructSYNFrame(localMAC, gatewayMAC, decoyIP.To4(), targetIP.To4(), srcPort, uint16(port))

					xdpTxLock.Lock()
					defer xdpTxLock.Unlock()

					descs := xsk.GetDescs(1)
					if len(descs) > 0 {
						copy(xsk.GetFrame(descs[0]), frame)
						descs[0].Len = uint32(len(frame))
						xsk.Transmit(descs)
					}
				}(decoyIP)
			}
		}
	}

	targetIP := net.ParseIP(ip)
	srcPort := getSrcPort(opts)

	var relayIP net.IP
	if opts != nil {
		relayIP = net.ParseIP(opts.RelayServer)
	}

	effectiveSrcIP := localIP.To4()
	if spoofedSrcIP != nil {
		effectiveSrcIP = spoofedSrcIP.To4()
	}

	if relayIP != nil {
		log.Printf("[*] Using relay server %s for IP-in-IP encapsulation.", relayIP.String())
	}
	rawFrame := constructSYNFrame(localMAC, gatewayMAC, effectiveSrcIP, targetIP, srcPort, uint16(port))

	var framesToSend [][]byte
	if opts != nil && opts.Fragment {
		mtu := 8
		framesToSend = evasion.FragmentPacket(rawFrame, mtu)
	} else if relayIP != nil {

		framesToSend = [][]byte{constructIPinIPEthernetFrame(localMAC, gatewayMAC, localIP.To4(), relayIP.To4(), rawFrame)}
	} else {
		framesToSend = [][]byte{rawFrame}
	}

	key := fmt.Sprintf("%s:%d", targetIP.String(), port)
	attemptTimeout := probeTimeout(rtt, timeout)
	attempts := probeAttempts(opts)
	var lastLatency time.Duration

	for attempt := 0; attempt < attempts; attempt++ {
		t0 := time.Now()
		if !transmitXDPFrames(xsk, framesToSend) {
			return TargetResult{
				IP:     ip,
				Port:   port,
				State:  StateFiltered,
				Reason: "XDP TX Ring Congestion (Fragment dropped)",
			}
		}

		deadline := time.Now().Add(attemptTimeout)
		for time.Now().Before(deadline) {
			if val, ok := xdpResults.LoadAndDelete(key); ok {
				resp := val.(xdpResponse)
				state := resp.state
				reason := "SYN-ACK Received (AF_XDP)"
				latency := time.Since(t0)
				if rtt != nil {
					rtt.Sample(latency)
				}

				osName := resp.osName
				if state == StateOpen && resp.osSig != "" {
					reason = fmt.Sprintf("SYN-ACK [%s]", resp.osSig)
					if osName != "" {
						reason = fmt.Sprintf("%s, guessed OS: %s (%.0f%% confidence)", reason, osName, resp.osConfidence*100)
					}
				} else if state == StateClosed {
					reason = "RST Received (AF_XDP)"
				}
				return TargetResult{
					IP: ip, Port: port, State: state, Reason: reason,
					OS: osName, Latency: latency, LatencyMs: float64(latency.Microseconds()) / 1000.0,
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		lastLatency = time.Since(t0)
	}

	return TargetResult{
		IP:        ip,
		Port:      port,
		State:     StateFiltered,
		Reason:    "No Response (Timeout)",
		Latency:   lastLatency,
		LatencyMs: float64(lastLatency.Microseconds()) / 1000.0,
	}
}

func ScanXDPUDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, rtt *RTTEstimator) TargetResult {
	xsk, ok := GlobalXsk.(*xdp.Socket)
	if !ok || xsk == nil {
		return TargetResult{IP: ip, Port: port, State: StateClosed, Reason: "XDP engine offline"}
	}

	if opts != nil && opts.DecoyIPs != "" {
		decoys, err := evasion.ParseDecoys(opts.DecoyIPs)
		if err == nil {
			targetIP := net.ParseIP(ip)
			srcPort := getSrcPort(opts)
			for _, decoyIP := range decoys {
				go func(decoyIP net.IP) {
					var payload []byte
					frame := constructUDPFrame(localMAC, gatewayMAC, decoyIP.To4(), targetIP.To4(), srcPort, uint16(port), payload)

					xdpTxLock.Lock()
					defer xdpTxLock.Unlock()

					descs := xsk.GetDescs(1)
					if len(descs) > 0 {
						copy(xsk.GetFrame(descs[0]), frame)
						descs[0].Len = uint32(len(frame))
						xsk.Transmit(descs)
					}
				}(decoyIP)
			}
		}
	}

	targetIP := net.ParseIP(ip)
	srcPort := getSrcPort(opts)

	var relayIP net.IP
	if opts != nil {
		relayIP = net.ParseIP(opts.RelayServer)
	}

	effectiveSrcIP := localIP.To4()
	if spoofedSrcIP != nil {
		effectiveSrcIP = spoofedSrcIP.To4()
	}

	if relayIP != nil {
		log.Printf("[*] Using relay server %s for IP-in-IP encapsulation.", relayIP.String())
	}

	var payload []byte
	if opts != nil && opts.DataString != "" {
		payload = []byte(opts.DataString)
	} else {

		switch port {
		case 53:

			payload = []byte{
				0xDB, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x01,
				0x00, 0x01,
			}
		}
	}

	rawFrame := constructUDPFrame(localMAC, gatewayMAC, effectiveSrcIP, targetIP, srcPort, uint16(port), payload)

	var framesToSend [][]byte
	if opts != nil && opts.Fragment {
		mtu := 8
		framesToSend = evasion.FragmentPacket(rawFrame, mtu)
	} else if relayIP != nil {

		framesToSend = [][]byte{constructIPinIPEthernetFrame(localMAC, gatewayMAC, localIP.To4(), relayIP.To4(), rawFrame)}
	} else {
		framesToSend = [][]byte{rawFrame}
	}

	key := fmt.Sprintf("%s:%d", targetIP.String(), port)
	attemptTimeout := probeTimeout(rtt, timeout)
	attempts := probeAttempts(opts)
	var lastLatency time.Duration

	for attempt := 0; attempt < attempts; attempt++ {
		t0 := time.Now()
		if !transmitXDPFrames(xsk, framesToSend) {
			return TargetResult{
				IP:     ip,
				Port:   port,
				State:  StateFiltered,
				Reason: "XDP TX Ring Congestion (Fragment dropped)",
			}
		}

		deadline := time.Now().Add(attemptTimeout)
		for time.Now().Before(deadline) {
			if val, ok := xdpResults.LoadAndDelete(key); ok {
				resp := val.(xdpResponse)
				state := resp.state
				latency := time.Since(t0)
				if rtt != nil {
					rtt.Sample(latency)
				}
				var reason string
				switch state {
				case StateOpen:
					reason = "UDP Response Received (AF_XDP)"
				case StateClosed:
					reason = "ICMP Port Unreachable (AF_XDP)"
				}
				return TargetResult{
					IP: ip, Port: port, State: state, Reason: reason,
					Latency: latency, LatencyMs: float64(latency.Microseconds()) / 1000.0,
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		lastLatency = time.Since(t0)
	}

	return TargetResult{
		IP:        ip,
		Port:      port,
		State:     StateOpenFiltered,
		Reason:    "No Response (Timeout)",
		Latency:   lastLatency,
		LatencyMs: float64(lastLatency.Microseconds()) / 1000.0,
	}
}
