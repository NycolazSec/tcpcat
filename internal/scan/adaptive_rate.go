package scan

import (
	"sync/atomic"
	"time"
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
	ratePPS  atomic.Int64
	minPPS   int64
	maxPPS   int64
	sent     atomic.Uint64
	lost     atomic.Uint64
	lastTick atomic.Int64 // UnixNano of the last granted send slot
}

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
// current rate. Safe to call from any number of goroutines concurrently.
func (rl *AdaptiveRateLimiter) Wait() {
	for {
		interval := time.Second.Nanoseconds() / rl.ratePPS.Load()
		if interval < 1 {
			interval = 1
		}

		last := rl.lastTick.Load()
		now := time.Now().UnixNano()
		next := last + interval
		if now < next {
			time.Sleep(time.Duration(next - now))
			continue
		}
		if rl.lastTick.CompareAndSwap(last, now) {
			return
		}
		// Lost the race with another goroutine claiming this slot; retry.
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
