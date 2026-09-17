//go:build linux

package scan

import (
	"log"
	"runtime"

	"golang.org/x/sys/unix"
)

// Busy-poll and CPU pinning turn the AF_XDP receive path from an
// interrupt-driven one -- where each burst of replies wakes a softirq, the
// scheduler migrates a goroutine, and the packet crosses cores before it
// is read -- into a tight, single-core spin. At the multi-Mpps rates a SYN
// sweep produces, that difference is what keeps the RX ring from
// overflowing (dropped replies read as filtered ports) and keeps CPU off
// the softirq path.
//
// These are best-effort optimizations, never hard requirements:
//   - The busy-poll sockopts only touch tcpcat's own XSK fd (no
//     system-wide effect) and are silently skipped on kernels older than
//     5.11 that lack SO_PREFER_BUSY_POLL.
//   - CPU pinning only affects tcpcat's own RX threads.
//
// The one thing this code deliberately does NOT do is rewrite the
// interface's system-wide NAPI tunables (napi_defer_hard_irqs,
// gro_flush_timeout, threaded NAPI) -- those are the operator's NIC, shared
// with everything else on the box, so they are surfaced as a one-time hint
// (logNAPITuningHint) rather than silently changed underneath the operator.

const (
	// busyPollUsec is how long, in microseconds, the socket may spin
	// polling the NIC before yielding. 20µs is the value the kernel's own
	// AF_XDP samples use: long enough to catch a reply burst, short enough
	// not to burn a core when the wire is idle between probes.
	busyPollUsec = 20
	// busyPollBudget caps how many frames one busy-poll pass drains, so a
	// flood can't starve the rest of the loop (fill-ring refill, TX).
	busyPollBudget = 64
)

// enableBusyPoll switches one XSK fd into preferred busy-poll mode. It logs
// and continues on any failure: busy-poll is a latency/throughput
// optimization, and a kernel without it should still scan, just via the
// ordinary interrupt path.
func enableBusyPoll(fd int) {
	// SO_PREFER_BUSY_POLL must come first: it tells NAPI to hand the socket
	// to userspace busy-polling instead of scheduling a softirq. Without
	// it the other two sockopts still "work" but the kernel keeps driving
	// the queue by interrupt, so the spin buys nothing.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PREFER_BUSY_POLL, 1); err != nil {
		log.Printf("[!] AF_XDP busy-poll unavailable (SO_PREFER_BUSY_POLL: %v); using interrupt-driven RX. Needs Linux 5.11+.", err)
		return
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BUSY_POLL, busyPollUsec); err != nil {
		log.Printf("[!] AF_XDP SO_BUSY_POLL failed (%v); busy-poll preference set but spin budget is the kernel default.", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BUSY_POLL_BUDGET, busyPollBudget); err != nil {
		// EPERM here is common: SO_BUSY_POLL_BUDGET above the default needs
		// CAP_NET_ADMIN. Not fatal -- the default budget still applies.
		log.Printf("[!] AF_XDP SO_BUSY_POLL_BUDGET failed (%v); using the kernel's default budget.", err)
	}
}

// pinToCPU locks the calling goroutine to its OS thread and pins that
// thread to one CPU. Called at the top of each per-queue RX goroutine so a
// queue's replies are drained on a stable core rather than chasing the
// goroutine around the scheduler. The lock is never released: the RX
// goroutine runs for the life of the scan and the runtime frees the thread
// when it exits.
func pinToCPU(cpu int) {
	n := runtime.NumCPU()
	if n == 0 {
		return
	}
	cpu %= n

	runtime.LockOSThread()

	var set unix.CPUSet
	set.Zero()
	set.Set(cpu)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		// Pinning is an optimization; an unpinned RX loop still works.
		// Unlock so the runtime can reuse the thread freely.
		runtime.UnlockOSThread()
		log.Printf("[!] Could not pin RX loop to CPU %d (%v); running unpinned.", cpu, err)
	}
}

// logNAPITuningHint prints the two sysfs writes that make busy-poll
// actually preempt the interrupt path. They are system-wide NIC settings,
// so tcpcat recommends rather than imposes them.
func logNAPITuningHint(iface string) {
	log.Printf("[*] For maximum AF_XDP throughput, defer this NIC's hard IRQs so busy-poll can take over:")
	log.Printf("      echo 2 | sudo tee /sys/class/net/%s/napi_defer_hard_irqs", iface)
	log.Printf("      echo 200000 | sudo tee /sys/class/net/%s/gro_flush_timeout", iface)
}
