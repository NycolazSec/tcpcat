package scan

import (
	"fmt"
	"sync"
	"time"

	"github.com/NycolazSec/tcpcat/config"
)

// maxProbeWindow is the most probes the adaptive window lets be in flight at
// once. Probes on the raw paths share one send socket and one receive loop,
// so this costs goroutines (one per slot), not file descriptors.
const maxProbeWindow = 4096

// probeWindowGrowth is how much a first-attempt reply grows the window once
// out of slow start: about 1.5% per round trip, since a round trip brings
// about one reply per slot. A power of two, so the arithmetic is exact.
const probeWindowGrowth = 1.0 / 64

// probeWindow bounds how many probes are in flight at once on the raw packet
// paths when the user did not choose a worker count with -w.
//
// Each worker waits for its probe's reply, so a scan's throughput is about
// (probes in flight) / (round trip). A fixed count sized from the CPU (cores
// x 32) is plenty on a LAN but caps a scan across a real network: 128
// workers at 11 ms is about 11,700 probes/s, whatever --rate says. Too many
// in flight, on the other hand, overflows a queue somewhere on the path and
// probes get lost.
//
// So the window starts at the CPU-based count and moves like a TCP
// congestion window:
//
//   - a reply to a probe's first attempt grows it: by one slot per reply
//     (slow start, about doubling per round trip) until the first congestion
//     signal, then by about 1.5% per round trip;
//   - a queue shows as delay before it overflows, so growth stops while the
//     smoothed round trip is more than twice the fastest one seen (plus 2 ms
//     of slack for scheduling noise), and that also ends slow start. Without
//     this, slow start overshoots: a loss is only noticed after a probe's
//     timeout, and the window keeps doubling until then (the same problem
//     TCP's HyStart addresses);
//   - a reply that only came after a retransmission means an earlier attempt
//     was lost or delayed past its timeout, the congestion signal Nmap also
//     relies on. The window drops to 70%, at most once per round trip, so
//     one burst of losses counts as one event;
//   - a port that never answers says nothing: a firewall that drops probes is
//     not congestion, so silence leaves the window alone.
//
// The window never shrinks below its starting size, which is what tcpcat
// always used, so a lossy path is scanned no slower than before. It never
// grows past maxProbeWindow, and with a --rate ceiling never past twice what
// that rate needs in flight (rate x smoothed RTT): more would only queue in
// the pacer.
type probeWindow struct {
	mu       sync.Mutex
	cond     *sync.Cond
	inflight int
	size     float64
	ssthresh float64
	floor    float64
	ceil     float64
	ratePPS  float64 // 0: no rate ceiling
	rtt      *RTTEstimator
	minRTT   time.Duration // fastest first-attempt reply seen; 0 until one
	lastCut  time.Time
	now      func() time.Time

	peak     float64
	cuts     int
	answered int // probes that got any reply
	retried  int // of those, replies that needed a retransmission
}

// probeWindowStats is what a scan reports about its window at the end.
type probeWindowStats struct {
	Start, Peak, Final int
	Cuts               int
	Answered, Retried  int
}

func newProbeWindow(start, ceil, ratePPS int, rtt *RTTEstimator) *probeWindow {
	if start < 1 {
		start = 1
	}
	if ceil < start {
		ceil = start
	}
	w := &probeWindow{
		size:     float64(start),
		ssthresh: float64(ceil),
		floor:    float64(start),
		ceil:     float64(ceil),
		ratePPS:  float64(ratePPS),
		rtt:      rtt,
		now:      time.Now,
		peak:     float64(start),
	}
	w.cond = sync.NewCond(&w.mu)
	return w
}

// acquire blocks until the probe can be sent without exceeding the window.
func (w *probeWindow) acquire() {
	w.mu.Lock()
	for w.inflight >= int(w.size) {
		w.cond.Wait()
	}
	w.inflight++
	w.mu.Unlock()
}

// release returns a probe's slot. attempt is the 1-based attempt whose reply
// settled the port, or 0 when no reply came at all (or the scan path does
// not report it), which leaves the window as it is. latency is that reply's
// round trip.
func (w *probeWindow) release(attempt int, latency time.Duration) {
	w.mu.Lock()
	w.inflight--
	switch {
	case attempt == 1:
		w.answered++
		if latency > 0 && (w.minRTT == 0 || latency < w.minRTT) {
			w.minRTT = latency
		}
		switch {
		case w.queueing():
			if w.size < w.ssthresh {
				w.ssthresh = w.size // delay rose before any loss: leave slow start
			}
		case w.size < w.ssthresh:
			w.size++
		default:
			w.size += probeWindowGrowth
		}
		if lim := w.limit(); w.size > lim {
			w.size = lim
		}
		if w.size > w.peak {
			w.peak = w.size
		}
	case attempt > 1:
		w.answered++
		w.retried++
		if now := w.now(); now.Sub(w.lastCut) >= w.cutInterval() {
			w.size = w.size * 7 / 10
			if w.size < w.floor {
				w.size = w.floor
			}
			w.ssthresh = w.size
			w.lastCut = now
			w.cuts++
		}
	}
	free := int(w.size) - w.inflight
	w.mu.Unlock()
	// Wake as many waiters as there are free slots (a grown window can free
	// more than one), but only a few per release: releases are frequent, so
	// any slot left over is picked up by the next one.
	for i := 0; i < free && i < 4; i++ {
		w.cond.Signal()
	}
}

// queueing reports whether replies are slowed by a queue on the path: the
// smoothed round trip is more than twice the fastest seen, plus 2 ms so that
// scheduling noise on a sub-millisecond LAN is not mistaken for one. Called
// with mu held.
func (w *probeWindow) queueing() bool {
	if w.minRTT == 0 || w.rtt == nil || !w.rtt.HasSamples() {
		return false
	}
	return w.rtt.SRTT() > 2*w.minRTT+2*time.Millisecond
}

// limit is the largest the window may currently grow to. Called with mu held.
func (w *probeWindow) limit() float64 {
	lim := w.ceil
	if w.ratePPS > 0 && w.rtt != nil && w.rtt.HasSamples() {
		if need := 2 * w.ratePPS * float64(w.rtt.SRTT()) / float64(time.Second); need < lim {
			lim = need
		}
	}
	if lim < w.floor {
		lim = w.floor
	}
	return lim
}

// cutInterval is how long after one decrease the next is allowed: one round
// trip, so the losses of one congestion episode count once. Called with mu
// held.
func (w *probeWindow) cutInterval() time.Duration {
	if w.rtt != nil && w.rtt.HasSamples() {
		if srtt := w.rtt.SRTT(); srtt > time.Millisecond {
			return srtt
		}
		return time.Millisecond
	}
	return 100 * time.Millisecond
}

func (w *probeWindow) stats() probeWindowStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return probeWindowStats{
		Start: int(w.floor), Peak: int(w.peak), Final: int(w.size),
		Cuts: w.cuts, Answered: w.answered, Retried: w.retried,
	}
}

// printProbeWindowSummary says how the window moved, and warns when replies
// often needed a retransmission: the path was dropping probes, so a port
// reported filtered may have been a loss rather than a firewall.
func printProbeWindowSummary(s probeWindowStats) {
	if s.Peak == s.Start && s.Retried == 0 {
		return
	}
	fmt.Printf("%s[*] Probes in flight: started at %d, peaked at %d, ended at %d (%d slowdown(s) on retransmitted replies)%s\n",
		config.White, s.Start, s.Peak, s.Final, s.Cuts, config.Reset)
	if s.Answered > 0 && s.Retried*100 >= s.Answered {
		fmt.Printf("%s[!] %d of %d replies (%.1f%%) needed a retransmission: the network dropped probes. "+
			"Ports reported filtered may be losses; a lower --rate or -w is more reliable.%s\n",
			config.Red, s.Retried, s.Answered, 100*float64(s.Retried)/float64(s.Answered), config.Reset)
	}
}
