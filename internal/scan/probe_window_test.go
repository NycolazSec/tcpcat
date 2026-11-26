package scan

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NycolazSec/tcpcat/config"
)

// fakeClock lets the tests decide when a round trip has passed.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestWindow(start, ceil, rate int, srtt time.Duration) (*probeWindow, *fakeClock) {
	rtt := NewRTTEstimator()
	if srtt > 0 {
		rtt.Sample(srtt)
	}
	w := newProbeWindow(start, ceil, rate, rtt)
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	w.now = clock.now
	return w, clock
}

// cycle runs one probe through the window: acquire, then release with the
// attempt that answered it and a round trip that shows no queueing.
func cycle(w *probeWindow, attempt int) {
	w.acquire()
	w.release(attempt, 10*time.Millisecond, 10*time.Millisecond)
}

func TestProbeWindowSlowStartGrowsOnePerFirstAttemptReply(t *testing.T) {
	w, _ := newTestWindow(100, 4096, 0, 10*time.Millisecond)
	for i := 0; i < 50; i++ {
		cycle(w, 1)
	}
	if got := w.stats().Final; got != 150 {
		t.Fatalf("window after 50 first-attempt replies = %d, want 150", got)
	}
}

func TestProbeWindowSilenceWithoutRateCeilingLeavesItAlone(t *testing.T) {
	w, _ := newTestWindow(100, 4096, 0, 10*time.Millisecond)
	for i := 0; i < 500; i++ {
		cycle(w, 0) // filtered port: no reply on any attempt
	}
	s := w.stats()
	if s.Final != 100 || s.Cuts != 0 || s.Answered != 0 {
		t.Fatalf("silence moved the window: %+v", s)
	}
}

func TestProbeWindowRetransmittedReplyCutsToSeventyPercent(t *testing.T) {
	w, _ := newTestWindow(100, 4096, 0, 10*time.Millisecond)
	for i := 0; i < 900; i++ {
		cycle(w, 1)
	}
	if got := w.stats().Final; got != 1000 {
		t.Fatalf("setup: window = %d, want 1000", got)
	}
	cycle(w, 2)
	s := w.stats()
	if s.Final != 700 || s.Cuts != 1 || s.Retried != 1 {
		t.Fatalf("after one retransmitted reply: %+v, want final 700 and one cut", s)
	}
	// After the cut it grows by ~1.5% per round trip (700 replies x 1/64),
	// not by one slot per reply.
	for i := 0; i < 700; i++ {
		cycle(w, 1)
	}
	if got := w.stats().Final; got != 710 {
		t.Fatalf("congestion avoidance: window = %d after 700 replies, want 710", got)
	}
}

func TestProbeWindowCutsAtMostOncePerRoundTrip(t *testing.T) {
	w, clock := newTestWindow(100, 4096, 0, 10*time.Millisecond)
	for i := 0; i < 900; i++ {
		cycle(w, 1)
	}
	for i := 0; i < 20; i++ { // one burst of losses
		cycle(w, 3)
	}
	if s := w.stats(); s.Cuts != 1 || s.Final != 700 {
		t.Fatalf("one burst: %+v, want a single cut to 700", s)
	}
	clock.advance(11 * time.Millisecond) // a round trip later
	cycle(w, 2)
	if s := w.stats(); s.Cuts != 2 || s.Final != 490 {
		t.Fatalf("next round trip: %+v, want a second cut to 490", s)
	}
}

func TestProbeWindowNeverBelowStartOrAboveCeiling(t *testing.T) {
	w, clock := newTestWindow(128, 300, 0, 10*time.Millisecond)
	for i := 0; i < 1000; i++ {
		cycle(w, 1)
	}
	if got := w.stats().Final; got != 300 {
		t.Fatalf("window = %d, want the ceiling 300", got)
	}
	for i := 0; i < 20; i++ {
		clock.advance(time.Second)
		cycle(w, 2)
	}
	if got := w.stats().Final; got != 128 {
		t.Fatalf("window = %d after repeated losses, want the starting size 128", got)
	}
}

func TestProbeWindowRateBoundsTheWindow(t *testing.T) {
	// 25,000 pps at 11 ms needs ~275 in flight; the window stops at twice that.
	w, _ := newTestWindow(128, 4096, 25000, 11*time.Millisecond)
	for i := 0; i < 2000; i++ {
		cycle(w, 1)
	}
	if got := w.stats().Final; got != 550 {
		t.Fatalf("window = %d, want 550 (2 x 25000 pps x 11 ms)", got)
	}
	// The default 500 pps needs far less than the starting size: it stays put.
	w, _ = newTestWindow(128, 4096, 500, 11*time.Millisecond)
	for i := 0; i < 2000; i++ {
		cycle(w, 1)
	}
	if got := w.stats().Final; got != 128 {
		t.Fatalf("window at 500 pps = %d, want the starting size 128", got)
	}
}

func TestProbeWindowBoundsConcurrency(t *testing.T) {
	w, _ := newTestWindow(8, 8, 0, 0)
	var inflight, peak atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				w.acquire()
				n := inflight.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				time.Sleep(50 * time.Microsecond)
				inflight.Add(-1)
				w.release(1, 0, 0)
			}
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > 8 || p < 2 {
		t.Fatalf("peak in flight = %d, want between 2 and the window of 8", p)
	}
}

func TestProbeWindowStopsGrowingWhenDelayShowsAQueue(t *testing.T) {
	rtt := NewRTTEstimator()
	w := newProbeWindow(100, 4096, 0, rtt)
	// Slow start on an 11 ms path.
	for i := 0; i < 200; i++ {
		rtt.Sample(11 * time.Millisecond)
		w.acquire()
		w.release(1, 11*time.Millisecond, 11*time.Millisecond)
	}
	if got := w.stats().Final; got != 300 {
		t.Fatalf("slow start: window = %d, want 300", got)
	}
	// A queue builds: replies now take 40 ms (> 2 x 11 ms + 2 ms). Once the
	// smoothed round trip crosses that (a few replies: it is an EWMA), the
	// window holds instead of doubling into a loss, and slow start is over.
	for i := 0; i < 500; i++ {
		rtt.Sample(40 * time.Millisecond)
		w.acquire()
		w.release(1, 40*time.Millisecond, 40*time.Millisecond)
	}
	s := w.stats()
	held := s.Final
	if held < 300 || held > 310 || s.Cuts != 0 {
		t.Fatalf("while queueing: %+v, want the window held near 300 with no cut", s)
	}
	// The queue drains: growth resumes, now by ~1.5% per round trip
	// (320 replies x 1/64 = 5 slots), not one slot per reply.
	for i := 0; i < 64; i++ {
		rtt.Sample(11 * time.Millisecond)
	}
	for i := 0; i < 320; i++ {
		rtt.Sample(11 * time.Millisecond)
		w.acquire()
		w.release(1, 11*time.Millisecond, 11*time.Millisecond)
	}
	if got := w.stats().Final; got != held+5 {
		t.Fatalf("after the queue drained: window = %d, want %d (congestion avoidance)", got, held+5)
	}
}

func TestProbeWindowIgnoresSubMillisecondJitter(t *testing.T) {
	// On a LAN, 0.1 ms vs 1.5 ms is scheduling noise, not a queue.
	rtt := NewRTTEstimator()
	w := newProbeWindow(100, 4096, 0, rtt)
	for i := 0; i < 300; i++ {
		lat := 1500 * time.Microsecond
		if i%10 == 0 {
			lat = 100 * time.Microsecond
		}
		rtt.Sample(lat)
		w.acquire()
		w.release(1, lat, lat)
	}
	if got := w.stats().Final; got != 400 {
		t.Fatalf("window = %d, want 400 (slow start undisturbed)", got)
	}
}

func TestAdaptsProbeWindowOnlyForSharedSocketScans(t *testing.T) {
	targets := []string{"192.0.2.10"}
	tests := []struct {
		name string
		opts config.Options
		want bool
	}{
		{"SYN scan, -w not given", config.Options{WorkersAuto: true, SynScan: true}, true},
		{"ACK scan, -w not given", config.Options{WorkersAuto: true, AckScan: true}, true},
		{"SYN scan with -w", config.Options{SynScan: true}, false},
		{"connect scan (a socket per probe)", config.Options{WorkersAuto: true, ConnectScan: true}, false},
		{"kernel UDP scan (a socket per probe)", config.Options{WorkersAuto: true, UdpScan: true}, false},
		{"idle scan (paced by the zombie)", config.Options{WorkersAuto: true, SynScan: true, ZombieHost: "192.0.2.5"}, false},
		{"no raw scan flag, no AF_XDP: connect scan", config.Options{WorkersAuto: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.opts
			if got := adaptsProbeWindow(&opts, targets); got != tt.want {
				t.Fatalf("adaptsProbeWindow() = %v, want %v", got, tt.want)
			}
		})
	}
}

// A host that drops most ports: every silent probe holds its slot for all its
// attempts. The window grows until it can sustain --rate, and stops there.
func TestProbeWindowSilenceGrowsUpToWhatTheRateNeeds(t *testing.T) {
	w, _ := newTestWindow(128, 4096, 1000, 10*time.Millisecond)
	for i := 0; i < 2000; i++ {
		w.acquire()
		w.release(0, 0, 750*time.Millisecond)
	}
	s := w.stats()
	if s.Final != 750 || s.Cuts != 0 {
		t.Fatalf("window = %d, want 750 (1000 probes/s x 0.75 s per silent probe): %+v", s.Final, s)
	}
}

// Silence right after a congestion cut is not trusted: losses look like
// silence too.
func TestProbeWindowSilenceDoesNotGrowRightAfterACut(t *testing.T) {
	w, clock := newTestWindow(100, 4096, 1000, 10*time.Millisecond)
	for i := 0; i < 300; i++ {
		cycle(w, 1)
	}
	clock.advance(time.Second)
	cycle(w, 2) // a retransmitted reply: congestion
	after := w.stats().Final
	for i := 0; i < 100; i++ {
		w.acquire()
		w.release(0, 0, 750*time.Millisecond)
	}
	if got := w.stats().Final; got != after {
		t.Fatalf("silence grew the window from %d to %d right after a cut", after, got)
	}
	clock.advance(time.Second)
	w.acquire()
	w.release(0, 0, 750*time.Millisecond)
	if got := w.stats().Final; got != after+1 {
		t.Fatalf("after a quiet period silence should grow it again: %d -> %d", after, got)
	}
}

// A few replies on a mostly-filtered host must not clamp back the window
// that silence grew for the rate.
func TestProbeWindowRepliesKeepTheRoomSilenceNeeds(t *testing.T) {
	w, _ := newTestWindow(128, 4096, 1000, 10*time.Millisecond)
	for i := 0; i < 2000; i++ {
		w.acquire()
		w.release(0, 0, 750*time.Millisecond)
	}
	cycle(w, 1) // an open port answers
	if got := w.stats().Final; got < 750 {
		t.Fatalf("one reply clamped the window to %d", got)
	}
}
