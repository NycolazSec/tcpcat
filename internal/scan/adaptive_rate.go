package scan

import (
	"sync/atomic"
	"time"

	"tcpcat/config"
)

// RTTEstimator maintains a smoothed round-trip time and its variance using
// the same fixed-point EWMA the Linux TCP stack uses for SRTT/RTTVAR
// (RFC 6298): alpha = 1/8 for the mean, beta = 1/4 for the variance. All
// state is stored in atomics so many worker goroutines can call Sample
// concurrently without a mutex.
type RTTEstimator struct {
	srtt   atomic.Int64
	rttvar atomic.Int64
	inited atomic.Bool
}

func NewRTTEstimator() *RTTEstimator {
	return &RTTEstimator{}
}

// Sample folds one new RTT observation into the estimate.
func (r *RTTEstimator) Sample(rtt time.Duration) {
	sample := int64(rtt)
	if sample <= 0 {
		return
	}

	if r.inited.CompareAndSwap(false, true) {
		r.srtt.Store(sample)
		r.rttvar.Store(sample / 2)
		return
	}

	for {
		oldSRTT := r.srtt.Load()
		delta := sample - oldSRTT
		newSRTT := oldSRTT + delta/8
		if !r.srtt.CompareAndSwap(oldSRTT, newSRTT) {
			continue // lost the race with another Sample call, retry
		}

		absDelta := delta
		if absDelta < 0 {
			absDelta = -absDelta
		}
		for {
			oldVar := r.rttvar.Load()
			newVar := oldVar + (absDelta-oldVar)/4
			if r.rttvar.CompareAndSwap(oldVar, newVar) {
				return
			}
		}
	}
}

// SRTT returns the current smoothed RTT estimate.
func (r *RTTEstimator) SRTT() time.Duration { return time.Duration(r.srtt.Load()) }

// HasSamples reports whether Sample has been called at least once, so
// callers can tell an estimate that's still just a floor apart from one
// actually derived from observed traffic.
func (r *RTTEstimator) HasSamples() bool { return r.inited.Load() }

// RTO returns a retransmission-timeout-style deadline (SRTT + 4*RTTVAR),
// floored at min so early, noisy samples can't collapse it to zero.
func (r *RTTEstimator) RTO(min time.Duration) time.Duration {
	rto := time.Duration(r.srtt.Load() + 4*r.rttvar.Load())
	if rto < min {
		return min
	}
	return rto
}

// AdaptiveRateLimiter paces probe emission using an AIMD (additive-increase,
// multiplicative-decrease) controller driven by observed loss, the same
// congestion-avoidance shape TCP uses. It is entirely lock-free: Wait and
// Report can both be called from many goroutines at once.
type AdaptiveRateLimiter struct {
	ratePPS        atomic.Int64
	minPPS         int64
	maxPPS         int64
	sent           atomic.Uint64
	lost           atomic.Uint64
	lastTick       atomic.Int64 // UnixNano of the last granted send slot
	batchRemaining atomic.Int64 // pre-paid slots left in the current pacerBatchSize batch
}

// pacerBatchSize is how many send slots acquireBatched reserves in one
// WaitN call instead of one. At tens of thousands of pps the per-packet
// interval is tens of microseconds, and calling time.Sleep that often
// doesn't scale: Go's runtime timer/scheduler overhead per wakeup can
// exceed the sleep duration itself, and at high concurrency this measurably
// caps real throughput far below the requested rate (observed: ~2500pps
// actual against a requested 25000pps on a 327k-job scan, with sys time
// dominating wall time -- exactly what a scheduler thrashing on ~300k
// individual sub-100us sleeps looks like). Reserving 64 evenly-spaced slots
// per WaitN call and handing them out one at a time amortizes that
// scheduling cost 64x while keeping the same average pps, at the cost of a
// small burst (up to 64 packets back-to-back) each time a batch refills.
const pacerBatchSize = 64

// NewAdaptiveRateLimiter starts pacing at initialPPS packets/sec and will
// never adjust the rate outside [minPPS, maxPPS].
func NewAdaptiveRateLimiter(initialPPS, minPPS, maxPPS int) *AdaptiveRateLimiter {
	if minPPS < 1 {
		minPPS = 1
	}
	if maxPPS < minPPS {
		maxPPS = minPPS
	}
	if initialPPS < minPPS {
		initialPPS = minPPS
	}
	if initialPPS > maxPPS {
		initialPPS = maxPPS
	}

	rl := &AdaptiveRateLimiter{minPPS: int64(minPPS), maxPPS: int64(maxPPS)}
	rl.ratePPS.Store(int64(initialPPS))
	rl.lastTick.Store(time.Now().UnixNano())
	return rl
}

// Wait blocks until the next send slot is due, spacing calls evenly at the
// current rate. Equivalent to WaitN(1).
func (rl *AdaptiveRateLimiter) Wait() { rl.WaitN(1) }

// WaitN reserves n evenly-spaced send slots at the current rate and blocks
// until the first is due. It is the multi-packet form of Wait, used where a
// single scan job unconditionally emits more than one packet (decoys fire
// once per job regardless of the reply) -- charging one slot per job for
// those keeps the real TX rate at the requested pps instead of a multiple
// of it, which is what turns a fast scan into an RX-side packet storm.
//
// Retransmits are different: whether a job needs 1 attempt or all of
// probeAttempts isn't known upfront, so those are paced individually via
// pacedWait() right before each actual transmit (see engine.go/xdp.go et
// al.), not reserved in bulk here. Reserving the worst case for every job
// regardless of whether it retransmits used to throttle real throughput to
// a fraction of the requested rate on a healthy, low-loss network, where
// most probes never retry at all.
//
// Strict even spacing is deliberate, and is why this is a pacer rather than
// a classic token bucket: the goal is to *smooth* the returning flood, and
// a token bucket's burst-up-to-capacity allowance would just recreate that
// flood in chunks. Idle time is never banked (a long-quiet limiter can't
// release a catch-up burst): the reserved window always starts no earlier
// than now. Lock-free; safe from many goroutines at once.
func (rl *AdaptiveRateLimiter) WaitN(n int) {
	if n <= 0 {
		return
	}
	for {
		interval := time.Second.Nanoseconds() / rl.ratePPS.Load()
		if interval < 1 {
			interval = 1
		}
		span := interval * int64(n)

		last := rl.lastTick.Load()
		now := time.Now().UnixNano()

		// lastTick is the next free instant; start there, or at now if the
		// limiter has been idle, so idle time isn't banked into a burst.
		start := last
		if now > start {
			start = now
		}
		if rl.lastTick.CompareAndSwap(last, start+span) {
			if wait := start - now; wait > 0 {
				time.Sleep(time.Duration(wait))
			}
			return
		}
		// Lost the race for this window with another goroutine; retry.
	}
}

// acquireBatched consumes one pre-paid slot from the current pacerBatchSize
// batch, refilling via a single WaitN(pacerBatchSize) call whenever the
// batch is exhausted. Lock-free: many goroutines can call this concurrently,
// and exactly one of them pays the refill's sleep while the rest either
// consume from the batch it just paid for or race to refill it themselves.
func (rl *AdaptiveRateLimiter) acquireBatched() {
	for {
		rem := rl.batchRemaining.Load()
		if rem > 0 {
			if rl.batchRemaining.CompareAndSwap(rem, rem-1) {
				return // pre-paid by an earlier refill -- no sleep needed
			}
			continue // lost the race for this slot; retry
		}
		// Batch exhausted: try to become the refiller. Losers of this CAS
		// loop back around and either see the new batch (if this goroutine
		// won) or try to refill it themselves (if a third goroutine won).
		if rl.batchRemaining.CompareAndSwap(rem, pacerBatchSize-1) {
			rl.WaitN(pacerBatchSize) // one sleep for the whole batch
			return
		}
	}
}

// pacedWait blocks for one packet's worth of limiter, if non-nil (a nil
// limiter means --rate wasn't set, or --unsafe-no-limits was: see
// NewLimiterFromOptions). Called right before each real packet transmission
// in a probeAttempts retry loop -- the first attempt included -- so the
// requested --rate governs actual packets sent, not a pre-reserved
// worst-case budget per job (see the WaitN doc comment). Threaded through
// as an explicit parameter from Engine.limiter rather than a package
// global: the web server (internal/web) can run more than one Engine
// concurrently, each against its own scan, and a shared global would let
// one request's rate limit pace another's packets or get nulled out from
// under it when the other finishes first.
//
// Goes through acquireBatched rather than WaitN(1) directly: at tens of
// thousands of pps the per-packet interval is tens of microseconds, and a
// scan with hundreds of thousands of jobs calling time.Sleep that often
// individually hits Go's scheduling overhead hard enough to cap real
// throughput at a small fraction of the requested rate (see pacerBatchSize).
func pacedWait(limiter *AdaptiveRateLimiter) {
	if limiter != nil {
		limiter.acquireBatched()
	}
}

// windowSize is how many samples are folded into each AIMD decision. Small
// enough to react within a fraction of a second at typical scan rates,
// large enough that a handful of stray timeouts don't trigger a
// multiplicative decrease on their own.
const windowSize = 64

// Report feeds one completed probe's outcome back into the controller.
// lost should be true for a timeout/no-response, false for any observed
// reply (open, closed, or filtered-with-signal all count as "not lost").
func (rl *AdaptiveRateLimiter) Report(lost bool) {
	sent := rl.sent.Add(1)
	if lost {
		rl.lost.Add(1)
	}
	if sent < windowSize {
		return
	}
	if !rl.sent.CompareAndSwap(sent, 0) {
		return // another goroutine already claimed this window
	}
	lostCount := rl.lost.Swap(0)
	lossPct := float64(lostCount) / float64(sent) * 100

	for {
		cur := rl.ratePPS.Load()
		var next int64
		switch {
		case lossPct < 0.5:
			next = cur + cur/20 // +5%: additive increase
		case lossPct > 3.0:
			next = cur / 2 // multiplicative decrease
		default:
			return // within the healthy band, hold steady
		}
		if next < rl.minPPS {
			next = rl.minPPS
		}
		if next > rl.maxPPS {
			next = rl.maxPPS
		}
		if rl.ratePPS.CompareAndSwap(cur, next) {
			return
		}
	}
}

// CurrentRate returns the controller's current target rate in packets/sec.
func (rl *AdaptiveRateLimiter) CurrentRate() int64 { return rl.ratePPS.Load() }

// NewLimiterFromOptions builds the pacer a scan phase should send through,
// or nil when the user has disabled pacing. Both the port-scan engine and
// AF_XDP host discovery go through this, so --rate means the same thing in
// each: discovery used to bypass pacing entirely and fire every probe as
// fast as the TX ring accepted it, which on a large range put far more
// packets on the wire than the requested rate before the scan proper had
// even started.
func NewLimiterFromOptions(opts *config.Options) *AdaptiveRateLimiter {
	if opts == nil || opts.UnsafeNoLimits || opts.RateLimit <= 0 {
		return nil
	}
	initial := opts.RateLimit
	if opts.AdaptiveRate {
		return NewAdaptiveRateLimiter(initial, initial/10, initial*4)
	}
	return NewAdaptiveRateLimiter(initial, initial, initial)
}
