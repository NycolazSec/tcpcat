// Package otguard is a per-target circuit breaker for scanning fragile
// operational-technology devices (PLCs, IP cameras, building controllers).
// Such equipment can degrade or fall over under a scan that a server would
// not notice, so the guard watches each target's round-trip time and aborts
// the scan on that target the moment it looks distressed: either its latency
// rises well above the baseline it showed when healthy, or it stops
// answering after having answered. It holds no sockets and sends nothing of
// its own; the scan engine feeds it the timing it already measures.
package otguard

import (
	"fmt"
	"sync"
	"time"
)

// Guard tracks every target independently. The zero value is not usable;
// call New.
type Guard struct {
	riseFactor      float64 // trip when RTT exceeds baseline*riseFactor...
	riseStreak      int     // ...for this many replies in a row
	baselineSamples int     // healthy replies needed before a baseline is set
	maxConsecLoss   int     // consecutive no-replies (after baseline) that trip

	mu      sync.Mutex
	targets map[string]*state
}

type state struct {
	samples    int
	sum        time.Duration // of the first baselineSamples, to average
	baseline   time.Duration // set once samples == baselineSamples
	consecHigh int           // replies in a row above baseline*riseFactor
	consecLoss int
	tripped    bool
	reason     string
	at         time.Time
}

// Trip is one target the guard stopped scanning.
type Trip struct {
	Target string
	Reason string
	At     time.Time
}

// New builds a guard. riseFactor is the fraction above baseline RTT that
// trips the breaker (1.15 = +15%); baselineSamples is how many healthy
// replies establish the baseline; maxConsecLoss is how many replies in a row
// may be lost, after a baseline exists, before the target is treated as down.
// Out-of-range arguments fall back to sensible defaults.
func New(riseFactor float64, baselineSamples, maxConsecLoss int) *Guard {
	if riseFactor <= 1 {
		riseFactor = 1.15
	}
	if baselineSamples < 1 {
		baselineSamples = 8
	}
	if maxConsecLoss < 1 {
		maxConsecLoss = 5
	}
	return &Guard{
		riseFactor:      riseFactor,
		riseStreak:      3,
		baselineSamples: baselineSamples,
		maxConsecLoss:   maxConsecLoss,
		targets:         make(map[string]*state),
	}
}

// Observe feeds one probe's outcome for target: rtt is its round-trip time
// (meaningful only when lost is false), lost is true when nothing came back.
// It may trip the breaker for that target. It is safe for concurrent use and
// is a no-op once the target has tripped.
func (g *Guard) Observe(target string, rtt time.Duration, lost bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	st := g.targets[target]
	if st == nil {
		st = &state{}
		g.targets[target] = st
	}
	if st.tripped {
		return
	}

	if lost {
		// Losing replies only means the device is in trouble once it has
		// proven it was answering (a baseline exists); before that, a
		// no-reply is just a filtered or closed port, which is normal.
		if st.baseline > 0 {
			st.consecLoss++
			if st.consecLoss >= g.maxConsecLoss {
				g.trip(st, fmt.Sprintf("stopped responding (%d probes in a row with no reply after answering)", st.consecLoss))
			}
		}
		return
	}
	if rtt <= 0 {
		return
	}
	st.consecLoss = 0

	if st.samples < g.baselineSamples {
		st.sum += rtt
		st.samples++
		if st.samples == g.baselineSamples {
			st.baseline = st.sum / time.Duration(g.baselineSamples)
		}
		return
	}

	// Baseline established: trip only when the RTT stays above baseline*rise
	// for riseStreak replies in a row. A single slow reply bumps the streak
	// but the next normal one resets it, so a transient spike is ignored
	// while a sustained rise (the device actually struggling) trips.
	if rtt > time.Duration(float64(st.baseline)*g.riseFactor) {
		st.consecHigh++
		if st.consecHigh >= g.riseStreak {
			pct := (float64(rtt)/float64(st.baseline) - 1) * 100
			g.trip(st, fmt.Sprintf("latency rose %.0f%% above baseline (%v -> %v) for %d probes in a row",
				pct, st.baseline.Round(time.Microsecond), rtt.Round(time.Microsecond), st.consecHigh))
		}
	} else {
		st.consecHigh = 0
	}
}

// trip marks a target tripped; the caller holds g.mu.
func (g *Guard) trip(st *state, reason string) {
	st.tripped = true
	st.reason = reason
	st.at = time.Now()
}

// Tripped reports whether scanning of target has been aborted.
func (g *Guard) Tripped(target string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.targets[target]
	return st != nil && st.tripped
}

// Trips lists every target the guard stopped, for the run's summary and
// audit log.
func (g *Guard) Trips() []Trip {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Trip
	for target, st := range g.targets {
		if st.tripped {
			out = append(out, Trip{Target: target, Reason: st.reason, At: st.at})
		}
	}
	return out
}
