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
	"sync/atomic"
	"time"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/discovery"
	"github.com/NycolazSec/tcpcat/internal/evasion"
	"github.com/NycolazSec/tcpcat/internal/netiface"
	"github.com/NycolazSec/tcpcat/internal/osdetect"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var GlobalXsk any
var xdpLink link.Link

// xdpColl is the loaded eBPF collection (the tcpcat_xdp_hook program and
// the xsks_map it redirects into) -- kept as a package-level reference
// specifically so ShutdownXDPEngine can close it deterministically. Before
// this, the success path in InitXDPEngine let coll fall out of scope with
// no explicit Close() at all: the program/map were only ever released
// implicitly, whenever Go's GC happened to run the cilium/ebpf finalizer
// (not guaranteed to run before process exit at all) or, failing that, by
// the kernel's own process-exit fd cleanup -- both non-deterministic, and
// the latter is a very plausible source of a multi-second delay observed
// after "eBPF XDP hook detached successfully" prints but before the
// process actually exits (the xsks_map's own kernel-side teardown -- it
// holds live references to the AF_XDP socket fds -- still has to happen
// somewhere; better it happens explicitly, in order, right here, than as
// an unlogged side effect of exit_group() teardown).
var xdpColl *ebpf.Collection
var localMAC net.HardwareAddr
var gatewayMAC net.HardwareAddr
var localIP net.IP
var localSubnet *net.IPNet // the interface's own network, for deciding when ARP (rather than routing through the gateway) can reach a discovery target directly

// xdpDiscoverySrcPort is the fixed source port DiscoverHostsXDP's own
// SYN/443 and ACK/80 discovery probes use. Also baked into the eBPF
// classifier (see xdp_asm.go) as one of the destination ports it will
// redirect into the AF_XDP socket, alongside each run's actual scan source
// port -- shared here so the two can't drift apart.
const xdpDiscoverySrcPort = 54322

// xdpSockLock guards the AF_XDP sockets' frame bookkeeping. The xdp library
// keeps, per socket, a table of which UMEM frames are free plus scratch
// slices, with no locking of its own; the scan goroutines (transmit) and the
// RX loops (refill, receive, reclaim sent frames) all go through it. Unlocked,
// the same frame can be handed to the kernel for receiving and to a probe for
// sending at once, which loses one of the two.
var xdpSockLock sync.Mutex
var xdpDiscovery sync.Map // IP string -> true, populated by xdpRxLoop for host discovery
var xdpRunning bool
var xdpDebug bool            // gates informational (non-error) engine/eBPF diagnostics behind --debug
var xdpSockets []*xdp.Socket // one per bound RX queue; xdpSockets[0] is also GlobalXsk, the sole TX path

// xdpTxRingSize is the TX ring's size in descriptors, and xdpCopyMode is
// true when the sockets run in copy mode (see xdpKickTx). Both are set by
// InitXDPEngine.
var (
	xdpTxRingSize int
	xdpCopyMode   bool
)

// XDPCopyMode reports whether the engine InitXDPEngine started runs in copy
// mode (no zero-copy support in the driver: veth and most virtual NICs,
// generic attach). There every frame is still copied through the kernel and
// one thread owns the TX ring, so the raw-socket engine, which sends from
// every core, is faster.
func XDPCopyMode() bool { return xdpCopyMode }

// XDPNotProbed is how many probes of this scan could not be sent on any
// attempt (queue full, or transmit failed): their ports were never probed.
func XDPNotProbed() int64 { return xdpTxUnsent.Load() }

// xdpTxBroken is set once a transmit has failed for good (the interface went
// down, the socket is gone): no further frame is queued, and the remaining
// probes are reported as not probed instead of waiting on a dead ring.
var (
	xdpTxBroken   atomic.Bool
	xdpTxFailOnce sync.Once
)

// xdpTransmit is xsk.Transmit without its panic. The xdp library panics on
// any sendto error other than EINTR, EAGAIN or EBUSY -- ENETDOWN or ENXIO
// when the interface goes down mid-scan, for instance -- which took the
// whole scan down, from the flusher or from the RX loop sending a RST. It
// returns the error instead and marks the TX path broken.
func xdpTransmit(xsk *xdp.Socket, descs []xdp.Desc) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, err = 0, fmt.Errorf("%v", r)
			xdpTxBroken.Store(true)
			xdpTxFailOnce.Do(func() {
				log.Printf("[!] AF_XDP transmit failed (%v): no further probe can be sent; the remaining ports are reported as not probed.", err)
			})
		}
	}()
	return xsk.Transmit(descs), nil
}

// xdpSocketOptions sizes one queue's AF_XDP socket. The library's defaults
// (64-slot rings over 128 frames) are sized for a demo: a scan gets one reply
// per probe, so at a few thousand probes/s the TX ring fills and probes are
// never sent, and the fill ring runs dry and the kernel drops replies -- both
// of which read as filtered ports.
//
// Rings are 2048 slots, halved as queues are added so that all queues
// together stay around 8192 receive slots and 64 MiB of UMEM whatever the
// NIC. A socket gets four rings' worth of frames: the fill and RX rings can
// never hold more than half of them, so transmit always has frames left.
func xdpSocketOptions(queues int) *xdp.SocketOptions {
	ring := 2048
	for ring > 256 && queues*ring > 8192 {
		ring /= 2
	}
	return &xdp.SocketOptions{
		NumFrames:              4 * ring,
		FrameSize:              2048,
		FillRingNumDescs:       ring,
		CompletionRingNumDescs: ring,
		RxRingNumDescs:         ring,
		TxRingNumDescs:         ring,
	}
}

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

// xdpSocketZeroCopy reports whether the kernel actually placed this AF_XDP
// socket in zero-copy mode. tcpcat binds with the default flags (0), which
// tells the kernel to negotiate zero-copy when the driver supports it (only
// possible under a native-mode XDP attach) and silently fall back to copy
// mode otherwise. The negotiated result isn't visible from the bind call, so
// the only reliable way to know which one we got is to read it back from the
// XDP_OPTIONS socket option after bind. Any error is treated as "not
// zero-copy", since this only drives an informational log line.
func xdpSocketZeroCopy(xsk *xdp.Socket) bool {
	opts, err := unix.GetsockoptInt(xsk.FD(), unix.SOL_XDP, unix.XDP_OPTIONS)
	if err != nil {
		return false
	}
	return opts&unix.XDP_OPTIONS_ZEROCOPY != 0
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

var (
	xdpIfaceName string
	xdpGatewayIP net.IP   // default gateway on xdpIfaceName, nil if it has none
	nextHopMACs  sync.Map // next-hop IP string -> *nextHopEntry
)

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type nextHopEntry struct {
	once sync.Once
	mac  net.HardwareAddr
}

// dstMACFor returns the hardware address a frame for target must carry: the
// target's own on its local network, the default gateway's otherwise (see
// nexthop.go). Each next hop is resolved once -- from the kernel's ARP
// table, else by asking on the wire -- and cached, concurrent probes for
// the same hop waiting on a single resolution. An unresolvable hop falls
// back to broadcast, which most stacks ignore for TCP: the probe then reads
// as filtered, which is the truth for a host that doesn't answer ARP.
func dstMACFor(target net.IP) net.HardwareAddr {
	hop := nextHopIP(target, localSubnet, xdpGatewayIP)
	if hop == nil {
		return gatewayMAC
	}
	v, _ := nextHopMACs.LoadOrStore(hop.String(), &nextHopEntry{})
	entry := v.(*nextHopEntry)
	entry.once.Do(func() {
		entry.mac = resolveMAC(hop.String())
		if entry.mac == nil {
			entry.mac = broadcastMAC
		}
	})
	return entry.mac
}

func resolveMAC(ip string) net.HardwareAddr {
	if data, err := os.ReadFile("/proc/net/arp"); err == nil {
		if mac := lookupARPTable(string(data), xdpIfaceName, ip); mac != nil {
			return mac
		}
	}
	macs, err := discovery.ARPResolve([]string{ip}, xdpIfaceName, 400*time.Millisecond)
	if err != nil {
		return nil
	}
	return macs[ip]
}

// InitXDPEngine boots the AF_XDP engine on ifaceName, or on the
// auto-detected default-gateway interface when ifaceName is empty. An
// explicit interface (-i/--interface) is required for targets only
// reachable through a local virtual interface -- a Docker bridge (br-*), a
// VPN tunnel, or a secondary NIC -- since none of those are ever the
// default route's interface that auto-detection would otherwise pick.
//
// opts is only used to read this run's actual probe source port (see
// getSrcPort), which the generated eBPF classifier needs to know which
// TCP/UDP destination ports are ours to redirect -- see generateXDPCollection.
func InitXDPEngine(ifaceName string, opts *config.Options) (any, error) {
	xdpDebug = opts.Debug
	if xdpRunning {
		if xdpDebug {
			log.Println("[*] XDP engine already initialized.")
		}
		return GlobalXsk, nil
	}

	var ip net.IP
	var ipNet *net.IPNet
	var err error

	if ifaceName != "" {
		ip, ipNet, err = netiface.Lookup(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("interface %q network info error: %v", ifaceName, err)
		}
	} else {
		ifaceName, ip, ipNet, err = getDefaultNetworkInfo()
		if err != nil {
			return nil, fmt.Errorf("network interface detection error: %v", err)
		}
	}
	localIP = ip
	localSubnet = ipNet

	xdpIfaceName = ifaceName
	gatewayMAC = broadcastMAC
	if routes, err := os.ReadFile("/proc/net/route"); err == nil {
		xdpGatewayIP = parseDefaultGateway(string(routes), ifaceName)
	}
	if xdpGatewayIP != nil {
		if mac := resolveMAC(xdpGatewayIP.String()); mac != nil {
			gatewayMAC = mac
		}
	}
	if xdpDebug {
		gw := "none on this interface (on-link targets only)"
		if xdpGatewayIP != nil {
			gw = fmt.Sprintf("%s (%s)", xdpGatewayIP, gatewayMAC)
		}
		log.Printf("[*] Auto-detection: Interface '%s' (IP: %s) | Default gateway: %s", ifaceName, localIP.String(), gw)
	}

	spec, err := generateXDPCollection(getSrcPort(opts))
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

	// AF_XDP only reaches true zero-copy when the program is attached in the
	// driver's native receive path (XDPDriverMode): there the kernel can hand
	// frames straight into the socket's UMEM. XDPGenericMode (SKB) runs the
	// program after the kernel has already allocated an skb, which forces every
	// AF_XDP socket on this interface into copy mode no matter what bind flags
	// ask for. So try native first and fall back to generic -- many virtual
	// NICs (cloud instances, VMs, Linux bridges) only support generic, and
	// failing hard there would break --ebpf for the common case.
	attachMode := "native driver"
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		attachMode = "generic (SKB)"
	}
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to attach XDP hook (tried native driver and generic modes): %v", err)
	}
	xdpLink = l
	if xdpDebug {
		log.Printf("[+] eBPF hook attached in %s mode.", attachMode)
	}

	numQueues := getInterfaceRXQueueCount(ifaceName)
	sockOpts := xdpSocketOptions(numQueues)

	// Ask the kernel for zero-copy when the hook is attached natively: the
	// driver then DMAs frames straight into the socket's UMEM, no per-packet
	// copy. The asavie/xdp library takes the bind(2) flag from this package
	// variable. Generic (SKB) attach can never be zero-copy, so don't even
	// ask there. A native attach does not guarantee the driver supports
	// zero-copy either (many don't, and veth/virtual NICs never do), so the
	// loop below falls back to copy mode if the zero-copy bind is refused.
	if attachMode == "native driver" {
		xdp.DefaultSocketFlags = unix.XDP_ZEROCOPY
	} else {
		xdp.DefaultSocketFlags = unix.XDP_COPY
	}

	xdpSockets = make([]*xdp.Socket, 0, numQueues)
	for q := 0; q < numQueues; q++ {
		xsk, err := xdp.NewSocket(iface.Index, q, sockOpts)
		if err != nil && q == 0 && xdp.DefaultSocketFlags == unix.XDP_ZEROCOPY {
			// Native attach, but this driver/queue can't do zero-copy: the
			// bind is refused (EOPNOTSUPP). Drop to copy mode for every queue
			// and retry queue 0 once, rather than failing --ebpf entirely.
			if xdpDebug {
				log.Printf("[*] Zero-copy not available on %s (%v); using copy mode.", ifaceName, err)
			}
			xdp.DefaultSocketFlags = unix.XDP_COPY
			xsk, err = xdp.NewSocket(iface.Index, q, sockOpts)
		}
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
				return nil, fmt.Errorf("failed to bridge FD into xsks_map: %v", err)
			}
			log.Printf("[!] Could not map AF_XDP socket for queue %d into xsks_map (%v); continuing with %d queue(s)", q, err, len(xdpSockets))
			break
		}

		xdpSockets = append(xdpSockets, xsk)
	}

	zeroCopy := len(xdpSockets) > 0 && xdpSocketZeroCopy(xdpSockets[0])
	xdpCopyMode = !zeroCopy
	xdpTxRingSize = sockOpts.TxRingNumDescs

	// Busy-poll and CPU-pinning only pay off on the zero-copy path (a capable
	// NIC attached natively): there they keep the RX ring drained with low
	// latency and off the softirq path. In copy mode -- a virtual NIC, generic
	// attach, or a driver without zero-copy -- there is no DMA to win, so a
	// spinning pinned RX thread just burns a core and, on a busy or
	// virtualized host, steals a vCPU and serializes transmit through the
	// socket lock (measured: a loaded server ran the copy-mode scan at ~15k
	// pps against ~25k on an idle one). So in copy mode the RX loops run
	// interrupt-driven -- poll() blocks until replies arrive -- and unpinned,
	// which wakes the loop far less often and leaves transmit the lock.
	if zeroCopy {
		for _, xsk := range xdpSockets {
			enableBusyPoll(xsk.FD())
		}
	}

	if xdpDebug {
		dataPath, rxMode := "copy mode", "interrupt-driven RX"
		if zeroCopy {
			dataPath, rxMode = "zero-copy", "busy-poll RX"
		}
		log.Printf("[+] AF_XDP engine ready: %s attach, %s, %s, on %d RX queue(s).", attachMode, dataPath, rxMode, len(xdpSockets))
		if zeroCopy {
			logNAPITuningHint(ifaceName)
		}
	}

	xdpRunning = true
	for i, xsk := range xdpSockets {
		// One RX goroutine per queue. On the zero-copy path each is pinned to
		// its own core (queue i -> CPU i, wrapping) so a queue's replies drain
		// on a stable core; in copy mode it runs unpinned (see above).
		go xdpRxLoop(xsk, i, zeroCopy)
	}

	// One flusher batches every probe's frame onto the single TX ring.
	xdpTxQueue = make(chan xdpTxItem, xdpTxQueueLen)
	xdpTxUnsent.Store(0)
	go xdpTxFlusher(xdpSockets[0])

	xdpColl = coll
	return xdpSockets[0], nil
}

func ShutdownXDPEngine() {
	if !xdpRunning {
		return
	}
	xdpRunning = false

	if n := xdpTxUnsent.Load(); n > 0 {
		log.Printf("[!] %d probe(s) were never sent: the AF_XDP transmit queue stayed full for %s on every attempt. "+
			"Their ports are reported with reason %q, not as scanned. Lower -w or --rate and scan them again.",
			n, xdpTxEnqueueWait, xdpNotProbedReason)
	}

	if xdpLink != nil {
		t0 := time.Now()
		err := xdpLink.Close()
		elapsed := time.Since(t0)
		if err != nil {
			log.Printf("[!] Error while detaching the XDP hook (%s): %v", elapsed, err)
		} else if xdpDebug {
			log.Printf("[-] eBPF XDP hook detached successfully (%s).", elapsed)
		}
	}

	if xdpDebug {
		logXDPSocketStats()
	}

	t0 := time.Now()
	for _, xsk := range xdpSockets {
		_ = xsk.Close()
	}
	if xdpDebug {
		log.Printf("[-] %d AF_XDP socket(s) closed (%s).", len(xdpSockets), time.Since(t0))
	}
	xdpSockets = nil

	// Releases the loaded program and xsks_map deterministically, right
	// here, instead of leaving it to whenever (if ever) the Go GC runs
	// cilium/ebpf's finalizer, or to the kernel's own process-exit fd
	// cleanup -- either of which can turn into an unlogged multi-second
	// stall while the kernel synchronizes the map's teardown against the
	// AF_XDP sockets it referenced, especially on a virtual bridge/veth
	// interface in generic (SKB) XDP mode.
	if xdpColl != nil {
		if xdpDebug {
			log.Println("[*] Releasing eBPF program and maps (this can take a few seconds on some interfaces)...")
		}
		t0 = time.Now()
		xdpColl.Close()
		xdpColl = nil
		if xdpDebug {
			log.Printf("[-] eBPF program and maps released (%s).", time.Since(t0))
		}
	}
}

// logXDPSocketStats prints, per queue, how many replies reached user space
// and how many the kernel had to drop before they did. A reply dropped here
// never reaches its probe, so the port is retried or reported filtered: these
// counters are the engine's own packet-loss figure for a run.
func logXDPSocketStats() {
	for q, xsk := range xdpSockets {
		st, err := xsk.Stats()
		if err != nil {
			continue
		}
		k := st.KernelStats
		log.Printf("[*] AF_XDP queue %d: %d frames received, %d sent; dropped by the kernel: %d (RX ring full: %d, no free buffer: %d)",
			q, st.Received, st.Transmitted, k.Rx_dropped+k.Rx_ring_full, k.Rx_ring_full, k.Rx_fill_ring_empty_descs)
	}
}

// xdpRxLoop drains one AF_XDP socket's RX ring. On a multi-queue NIC,
// InitXDPEngine starts one of these per queue (each bound to its own
// xsks_map slot) since a NIC's RSS hashing can steer replies to any queue,
// not just the one the scan's own probes happen to transmit from; all of
// them deliver into the same shared xdpWaiters channels and xdpDiscovery map.
func xdpRxLoop(xsk *xdp.Socket, cpu int, busyPoll bool) {
	// Only pin to a stable core on the busy-poll (zero-copy) path. In copy
	// mode pinning to one (possibly contended) core hurts more than it helps,
	// so let the scheduler place this goroutine (see InitXDPEngine).
	if busyPoll {
		pinToCPU(cpu)
	}

	pfd := []unix.PollFd{{Fd: int32(xsk.FD()), Events: unix.POLLIN}}
	var batch []byte // this pass's frames, copied out back to back
	var ends []int   // end offset of each frame in batch

	for xdpRunning {
		xdpSockLock.Lock()
		xdpReclaimSent(xsk)
		if freeFill := xsk.NumFreeFillSlots(); freeFill > 0 {
			xsk.Fill(xsk.GetDescs(freeFill))
		}
		xdpSockLock.Unlock()

		// Wait for replies only (POLLIN). Asking for POLLOUT as well, as the
		// library's own Poll does, returns at once whenever the TX ring has
		// room, turning this loop into a spin for the whole scan.
		if _, err := unix.Poll(pfd, 50); err != nil {
			continue
		}

		// Receive marks a frame free again, so a probe may reuse it for its
		// own SYN the moment the lock is released: copy the replies out
		// (they are ~60 bytes each) and parse the copies.
		batch, ends = batch[:0], ends[:0]
		xdpSockLock.Lock()
		for _, desc := range xsk.Receive(xsk.NumReceived()) {
			batch = append(batch, xsk.GetFrame(desc)...)
			ends = append(ends, len(batch))
		}
		xdpSockLock.Unlock()

		start := 0
		for _, end := range ends {
			handleXDPFrame(xsk, batch[start:end])
			start = end
		}
	}
}

// handleXDPFrame parses one frame the eBPF classifier redirected to us and
// delivers what it says to the probe (or discovery sweep) waiting for it.
func handleXDPFrame(xsk *xdp.Socket, frame []byte) {
	if len(frame) < 14 {
		return
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])

	if etherType == 0x0806 { // ARP
		if len(frame) < 14+28 {
			return
		}
		arpStart := 14
		op := binary.BigEndian.Uint16(frame[arpStart+6 : arpStart+8])
		if op == 2 { // reply
			senderIP := net.IP(frame[arpStart+14 : arpStart+18])
			xdpDiscovery.Store(senderIP.String(), true)
		}
		return
	}

	if etherType != 0x0800 || len(frame) < 14+20 {
		return
	}

	ipStart := 14
	ipHeaderLen := int(frame[ipStart]&0x0F) * 4
	protocol := frame[ipStart+9]
	srcIP := net.IP(frame[ipStart+12 : ipStart+16])

	switch protocol {
	case 6:
		tcpStart := ipStart + ipHeaderLen
		if len(frame) < tcpStart+14 {
			return
		}
		pktSrcPort := binary.BigEndian.Uint16(frame[tcpStart : tcpStart+2])
		tcpFlags := frame[tcpStart+13]
		key := fmt.Sprintf("%s:%d", srcIP.String(), pktSrcPort)

		xdpDiscovery.Store(srcIP.String(), true) // any TCP reply proves the host is alive

		if (tcpFlags & 0x12) == 0x12 {
			osSig := osdetect.GenerateSignature(frame, ipStart, tcpStart)
			osName, osConfidence := osdetect.ClassifyOS(frame, ipStart, tcpStart)
			deliverXDPResult(key, xdpResponse{
				state:        StateOpen,
				osSig:        osSig,
				osName:       osName,
				osConfidence: osConfidence,
				// A SYN/ACK echoing MP_CAPABLE (kind 30) marks a
				// Multipath-TCP-capable target. Only meaningful when
				// --mptcp put the option in our SYN in the first place,
				// but reading it is free and never false-positives:
				// a stack that didn't negotiate MPTCP won't echo it.
				mptcp: osdetect.HasTCPOptionKind(frame, ipStart, tcpStart, mpCapableKind),
			})

			ourIP := net.IP(frame[ipStart+16 : ipStart+20])
			ourPort := binary.BigEndian.Uint16(frame[tcpStart+2 : tcpStart+4])
			ackSeq := binary.BigEndian.Uint32(frame[tcpStart+8 : tcpStart+12])
			sendRST(xsk, ourIP, srcIP, ourPort, pktSrcPort, ackSeq)
		} else if (tcpFlags & 0x04) != 0 {
			deliverXDPResult(key, xdpResponse{state: StateClosed})
		}

	case 17:
		udpStart := ipStart + ipHeaderLen
		if len(frame) < udpStart+8 {
			return
		}
		pktSrcPort := binary.BigEndian.Uint16(frame[udpStart : udpStart+2])
		key := fmt.Sprintf("%s:%d", srcIP.String(), pktSrcPort)
		deliverXDPResult(key, xdpResponse{state: StateOpen})

	case 1:
		icmpStart := ipStart + ipHeaderLen
		if len(frame) < icmpStart+8 {
			return
		}
		icmpType := frame[icmpStart]
		icmpCode := frame[icmpStart+1]

		if icmpType == 0 { // Echo Reply: host is alive
			xdpDiscovery.Store(srcIP.String(), true)
		} else if icmpType == 3 && icmpCode == 3 {
			originalIPStart := icmpStart + 8
			if len(frame) < originalIPStart+20+8 {
				return
			}
			originalIPHdrLen := int(frame[originalIPStart]&0x0F) * 4
			originalUDPStart := originalIPStart + originalIPHdrLen
			if len(frame) < originalUDPStart+4 {
				return // the quoted header claims options this frame doesn't carry
			}

			originalDstIP := net.IP(frame[originalIPStart+16 : originalIPStart+20])
			originalDstPort := binary.BigEndian.Uint16(frame[originalUDPStart+2 : originalUDPStart+4])

			key := fmt.Sprintf("%s:%d", originalDstIP.String(), originalDstPort)
			deliverXDPResult(key, xdpResponse{state: StateClosed})
		}
	}
}

type xdpResponse struct {
	state        string
	osSig        string
	osName       string
	osConfidence float64
	mptcp        bool
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
	frame := constructRSTFrame(localMAC, dstMACFor(dstIP), srcIP, dstIP, srcPort, dstPort, seq)

	// If the TX ring is momentarily full the RST is skipped: the target's
	// own SYN/ACK retransmit will get a fresh chance.
	xdpSockLock.Lock()
	xdpSendLocked(xsk, frame)
	xdpSockLock.Unlock()
}

// xdpReclaimSent takes back the frames the kernel has finished sending; until
// then they sit in the completion ring and can't carry another probe. The
// caller holds xdpSockLock.
func xdpReclaimSent(xsk *xdp.Socket) {
	if n := xsk.NumCompleted(); n > 0 {
		xsk.Complete(n)
	}
}

// xdpSendLocked queues one frame for transmission and reports whether the
// kernel took it: false means no free frame or a full TX ring, i.e. the
// frame was NOT sent. The caller holds xdpSockLock.
func xdpSendLocked(xsk *xdp.Socket, frame []byte) bool {
	descs := xsk.GetDescs(1)
	if len(descs) == 0 {
		xdpReclaimSent(xsk)
		if descs = xsk.GetDescs(1); len(descs) == 0 {
			return false
		}
	}
	copy(xsk.GetFrame(descs[0]), frame)
	descs[0].Len = uint32(len(frame))
	n, err := xdpTransmit(xsk, descs)
	return err == nil && n == 1
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
// txBatchSize is how many probe frames the flusher coalesces into a single
// Transmit (one sendto). AF_XDP has one TX ring, so every probe's frame is
// serialized through it; sending them one at a time is one sendto syscall per
// probe, which dominates the wall time in copy mode on a loaded or virtualized
// host. Batching amortizes the syscall over up to txBatchSize frames.
const txBatchSize = 64

// xdpTxItem is one frame on its way to the TX ring. When sent is not nil,
// the flusher reports on it whether the frame made it onto the ring (true)
// or was dropped for lack of a free frame (false).
type xdpTxItem struct {
	frame []byte
	sent  chan bool
}

// xdpTxQueue carries probe frames from the scanning goroutines to the single
// flusher that owns the TX ring.
var xdpTxQueue chan xdpTxItem

// xdpTxQueueLen is xdpTxQueue's capacity: a few batches, so paced bursts don't
// block, but short enough that a frame never waits long in it. A probe's
// timeout starts once its frame is queued, and the queue used to hold 8192
// frames: with many workers (-w 4096) it filled faster than the flusher
// drained it, queued probes timed out before leaving, their retries filled it
// further, and 91 % of a lab scan's probes were reported FILTERED without
// ever being sent (3 of 80 open ports found).
const xdpTxQueueLen = 8 * txBatchSize

// xdpTxEnqueueWait is how long a probe waits for room in a full xdpTxQueue
// before giving up on that attempt. Waiting slows the workers down to what
// the flusher can send, which is the point: a slower scan, not a wrong one.
var xdpTxEnqueueWait = 2 * time.Second

// xdpTxUnsent counts probes that gave up on every attempt because the queue
// stayed full: their ports were never probed. ShutdownXDPEngine reports it.
var xdpTxUnsent atomic.Int64

// xdpNotProbedReason is the Reason of a port whose probe never left tcpcat.
const xdpNotProbedReason = "Not probed: AF_XDP transmit queue saturated"

// xdpNotProbed is the Reason for a port whose probe never left: the queue
// stayed full, or the transmit path failed (see xdpTransmit).
func xdpNotProbed() string {
	if xdpTxBroken.Load() {
		return "Not probed: AF_XDP transmit failed"
	}
	return xdpNotProbedReason
}

// transmitXDPFrames hands a probe's frames to the TX flusher, waiting up to
// xdpTxEnqueueWait for room when the queue is full, then waits for the flusher
// to put the last of them on the TX ring. It returns false when they were not
// all sent, and the caller then retries the attempt or reports the port as
// not probed.
//
// Returning only once the frame is on the ring is what keeps local queueing
// out of the probe's timeout: the caller starts the attempt's clock on
// return. Started at enqueue, it ran while the frame waited behind thousands
// of others (53 ms median, 115 ms max for a reply on a veth with -w 4096),
// probes timed out before they had left, and open ports were lost.
//
// The frames must not be mutated afterwards: the flusher copies them into the
// UMEM when it sends. The socket argument is ignored (the flusher owns it).
func transmitXDPFrames(_ *xdp.Socket, frames [][]byte) bool {
	if len(frames) == 0 {
		return true
	}
	if xdpTxBroken.Load() {
		return false
	}
	deadline := time.NewTimer(xdpTxEnqueueWait)
	defer deadline.Stop()

	sent := make(chan bool, 1)
	for i, frame := range frames {
		item := xdpTxItem{frame: frame}
		if i == len(frames)-1 {
			item.sent = sent // frames leave in order: the last one marks the probe sent
		}
		select {
		case xdpTxQueue <- item:
		case <-deadline.C:
			return false
		}
	}
	select {
	case ok := <-sent:
		return ok
	case <-deadline.C:
		return false
	}
}

// xdpTxFlusher owns the TX ring: it drains xdpTxQueue, coalescing up to
// txBatchSize frames into one Transmit (one sendto). One flusher runs for the
// life of the engine, on xdpSockets[0] (the sole TX socket).
func xdpTxFlusher(xsk *xdp.Socket) {
	batch := make([]xdpTxItem, 0, txBatchSize)
	idle := time.NewTimer(time.Hour)
	defer idle.Stop()
	for xdpRunning {
		// Block for the first frame, with a timeout so the loop can exit.
		idle.Reset(2 * time.Millisecond)
		select {
		case it := <-xdpTxQueue:
			batch = append(batch, it)
		case <-idle.C:
			continue
		}
		// Take whatever else is already queued, up to the batch size.
	drain:
		for len(batch) < txBatchSize {
			select {
			case it := <-xdpTxQueue:
				batch = append(batch, it)
			default:
				break drain
			}
		}
		n := xdpFlushBatch(xsk, batch)
		for i, it := range batch {
			if it.sent != nil {
				it.sent <- i < n // buffered: never blocks the flusher
			}
		}
		batch = batch[:0]
	}
}

// xdpFlushBatch writes a batch of frames into the TX ring and kicks the kernel
// once for the whole batch. It returns how many of the batch's frames, from
// the start, made it onto the ring; the rest found no free frame and were not
// sent, which the flusher reports to their probes.
func xdpFlushBatch(xsk *xdp.Socket, items []xdpTxItem) int {
	if len(items) == 0 {
		return 0
	}
	xdpSockLock.Lock()
	defer xdpSockLock.Unlock()

	descs := xsk.GetDescs(len(items))
	if len(descs) < len(items) {
		xdpReclaimSent(xsk) // free completed frames, then try for more
		descs = xsk.GetDescs(len(items))
	}
	n := 0
	for ; n < len(descs) && n < len(items); n++ {
		copy(xsk.GetFrame(descs[n]), items[n].frame)
		descs[n].Len = uint32(len(items[n].frame))
	}
	if n > 0 {
		var err error
		if n, err = xdpTransmit(xsk, descs[:n]); err != nil { // one sendto for the whole batch
			return 0
		}
		xdpKickTx(xsk)
	}
	return n
}

// xdpTxKickLimit bounds the extra sendto calls one flush makes: enough for a
// full batch plus a backlog, never an unbounded loop under xdpSockLock.
const xdpTxKickLimit = 8

// xdpKickTx makes the kernel transmit what Transmit left in the TX ring.
//
// In copy mode (veth and most virtual NICs, generic attach, drivers without
// zero-copy) one sendto transmits at most 32 descriptors (TX_BATCH_SIZE in
// net/xdp/xsk.c) and returns EAGAIN for the rest, and the xdp library's
// Transmit stops at that EAGAIN. With txBatchSize (64) frames per flush, the
// ring then kept up to half of every batch: under load it filled (2048
// descriptors), its frames waited for later flushes, and new probes found no
// room: 4636 probes of a -w 4096 lab scan could not be sent.
//
// It kicks again while the kernel keeps consuming descriptors, and stops as
// soon as a kick makes no progress (the device is busy: the next flush tries
// again). In zero-copy mode the NIC consumes the ring asynchronously, so
// Transmit's own wakeup is all it needs. The caller holds xdpSockLock.
func xdpKickTx(xsk *xdp.Socket) {
	if !xdpCopyMode || xdpTxRingSize == 0 {
		return
	}
	pending := xdpTxRingSize - xsk.NumFreeTxSlots()
	for kicks := 0; pending > 0 && kicks < xdpTxKickLimit; kicks++ {
		_, _, errno := unix.Syscall6(unix.SYS_SENDTO, uintptr(xsk.FD()), 0, 0, uintptr(unix.MSG_DONTWAIT), 0, 0)
		switch errno {
		case 0, unix.EAGAIN, unix.EBUSY, unix.EINTR:
		default:
			return // a broken socket: the probes' timeouts report it
		}
		left := xdpTxRingSize - xsk.NumFreeTxSlots()
		if left >= pending {
			return // no progress
		}
		pending = left
	}
}

func ScanXDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, rtt *RTTEstimator, limiter *AdaptiveRateLimiter) TargetResult {
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
					frame := constructSYNFrame(localMAC, dstMACFor(targetIP), decoyIP.To4(), targetIP.To4(), srcPort, uint16(port), false)

					xdpSockLock.Lock()
					xdpSendLocked(xsk, frame)
					xdpSockLock.Unlock()
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
	rawFrame := constructSYNFrame(localMAC, dstMACFor(targetIP), effectiveSrcIP, targetIP, srcPort, uint16(port), opts != nil && opts.MPTCP)

	var framesToSend [][]byte
	if opts != nil && opts.Fragment {
		mtu := 8
		framesToSend = evasion.FragmentPacket(rawFrame, mtu)
	} else if relayIP != nil {

		framesToSend = [][]byte{constructIPinIPEthernetFrame(localMAC, dstMACFor(relayIP), localIP.To4(), relayIP.To4(), rawFrame)}
	} else {
		framesToSend = [][]byte{rawFrame}
	}

	key := fmt.Sprintf("%s:%d", targetIP.String(), port)
	attemptTimeout := probeTimeout(rtt, timeout)
	attempts := probeAttempts(opts)
	var lastLatency time.Duration
	unsent := 0 // attempts whose frame never got into the TX queue

	// Register the waiter before the first transmit: a same-subnet SYN-ACK
	// can return in under a millisecond, before this goroutine would reach
	// a poll, and the RX loop drops any reply with no waiter.
	ch, release := registerXDPWaiter(key)
	defer release()

	for attempt := 0; attempt < attempts; attempt++ {
		// Drop any reply left over from a previous attempt so this attempt's
		// timeout can't be satisfied by a stale frame.
		select {
		case <-ch:
		default:
		}

		pacedWait(limiter)
		if !transmitXDPFrames(xsk, framesToSend) {
			unsent++
			continue // not sent: try again rather than read silence into it
		}
		t0 := time.Now()

		select {
		case resp := <-ch:
			state := resp.state
			reason := "SYN-ACK Received (AF_XDP)"
			latency := time.Since(t0)
			if rtt != nil {
				rtt.Sample(latency)
			}

			osName := resp.osName
			if state == StateOpen && resp.osSig != "" {
				reason = fmt.Sprintf("SYN-ACK [%s]", resp.osSig)
			} else if state == StateClosed {
				reason = "RST Received (AF_XDP)"
			}
			if resp.mptcp {
				reason += " [MPTCP]"
			}
			// OS/OSConfidence are reported per-port (each SYN/ACK is its own
			// independent fingerprint sample) but only shown once per host on
			// the console -- see the per-host dedup in engine.go's result
			// printer -- rather than repeated in Reason on every open port.
			return TargetResult{
				IP: ip, Port: port, State: state, Reason: reason, MPTCP: resp.mptcp,
				OS: osName, OSConfidence: resp.osConfidence, Latency: latency, LatencyMs: float64(latency.Microseconds()) / 1000.0,
			}
		case <-time.After(attemptTimeout):
			lastLatency = time.Since(t0)
		}
	}

	if unsent == attempts {
		// Nothing was sent: this port's state is unknown, not filtered.
		xdpTxUnsent.Add(1)
		return TargetResult{IP: ip, Port: port, State: StateFiltered, Reason: xdpNotProbed()}
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

func ScanXDPUDPPort(ip string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, rtt *RTTEstimator, limiter *AdaptiveRateLimiter) TargetResult {
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
					frame := constructUDPFrame(localMAC, dstMACFor(targetIP), decoyIP.To4(), targetIP.To4(), srcPort, uint16(port), payload)

					xdpSockLock.Lock()
					xdpSendLocked(xsk, frame)
					xdpSockLock.Unlock()
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

	rawFrame := constructUDPFrame(localMAC, dstMACFor(targetIP), effectiveSrcIP, targetIP, srcPort, uint16(port), payload)

	var framesToSend [][]byte
	if opts != nil && opts.Fragment {
		mtu := 8
		framesToSend = evasion.FragmentPacket(rawFrame, mtu)
	} else if relayIP != nil {

		framesToSend = [][]byte{constructIPinIPEthernetFrame(localMAC, dstMACFor(relayIP), localIP.To4(), relayIP.To4(), rawFrame)}
	} else {
		framesToSend = [][]byte{rawFrame}
	}

	key := fmt.Sprintf("%s:%d", targetIP.String(), port)
	attemptTimeout := probeTimeout(rtt, timeout)
	attempts := probeAttempts(opts)
	var lastLatency time.Duration
	unsent := 0 // attempts whose frame never got into the TX queue

	// Register before transmit (see ScanXDPPort): the RX loop delivers a
	// reply straight into this channel and drops it if no waiter exists.
	ch, release := registerXDPWaiter(key)
	defer release()

	for attempt := 0; attempt < attempts; attempt++ {
		select {
		case <-ch:
		default:
		}

		pacedWait(limiter)
		if !transmitXDPFrames(xsk, framesToSend) {
			unsent++
			continue // not sent: try again rather than read silence into it
		}
		t0 := time.Now()

		select {
		case resp := <-ch:
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
		case <-time.After(attemptTimeout):
			lastLatency = time.Since(t0)
		}
	}

	if unsent == attempts {
		// Nothing was sent: this port's state is unknown, not filtered.
		xdpTxUnsent.Add(1)
		return TargetResult{IP: ip, Port: port, State: StateOpenFiltered, Reason: xdpNotProbed()}
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
