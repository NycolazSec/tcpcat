package otguard

import (
	"sync"
	"testing"
	"time"
)

// feed sends n healthy replies of the given rtt to establish/extend history.
func feed(g *Guard, target string, rtt time.Duration, n int) {
	for i := 0; i < n; i++ {
		g.Observe(target, rtt, false)
	}
}

func TestSteadyLatencyDoesNotTrip(t *testing.T) {
	g := New(1.15, 8, 5)
	feed(g, "plc", 2*time.Millisecond, 50)
	if g.Tripped("plc") {
		t.Fatal("steady latency should not trip the breaker")
	}
}

func TestLatencyRiseTrips(t *testing.T) {
	g := New(1.15, 8, 5)
	feed(g, "plc", 2*time.Millisecond, 8) // baseline = 2ms
	if g.Tripped("plc") {
		t.Fatal("should not trip while only the baseline is being set")
	}
	// Push latency to 10ms; the EWMA climbs past baseline*1.15 within a few
	// samples and trips.
	for i := 0; i < 20 && !g.Tripped("plc"); i++ {
		g.Observe("plc", 10*time.Millisecond, false)
	}
	if !g.Tripped("plc") {
		t.Fatal("a sustained latency rise well above baseline must trip")
	}
	trips := g.Trips()
	if len(trips) != 1 || trips[0].Target != "plc" {
		t.Fatalf("Trips() = %+v, want one trip for plc", trips)
	}
}

func TestOneSlowReplyDoesNotTrip(t *testing.T) {
	g := New(1.15, 8, 5)
	feed(g, "plc", 2*time.Millisecond, 8)
	g.Observe("plc", 50*time.Millisecond, false) // a single spike
	if g.Tripped("plc") {
		t.Fatal("a single slow reply should be smoothed, not trip the breaker")
	}
}

func TestStopsRespondingAfterBaselineTrips(t *testing.T) {
	g := New(1.15, 8, 5)
	feed(g, "cam", 3*time.Millisecond, 8) // healthy baseline
	for i := 0; i < 5; i++ {
		g.Observe("cam", 0, true) // five no-replies in a row
	}
	if !g.Tripped("cam") {
		t.Fatal("a device that stops answering after a baseline must trip")
	}
}

func TestLossBeforeBaselineIsIgnored(t *testing.T) {
	g := New(1.15, 8, 5)
	// Filtered/closed ports before any reply: normal, must not trip.
	for i := 0; i < 20; i++ {
		g.Observe("host", 0, true)
	}
	if g.Tripped("host") {
		t.Fatal("no-replies before a baseline exists are normal and must not trip")
	}
}

func TestRecoveryResetsLossStreak(t *testing.T) {
	g := New(1.15, 8, 5)
	feed(g, "plc", 2*time.Millisecond, 8)
	for i := 0; i < 4; i++ {
		g.Observe("plc", 0, true) // 4 losses, one short of tripping
	}
	g.Observe("plc", 2*time.Millisecond, false) // a reply resets the streak
	for i := 0; i < 4; i++ {
		g.Observe("plc", 0, true)
	}
	if g.Tripped("plc") {
		t.Fatal("a reply should reset the consecutive-loss streak")
	}
}

func TestTargetsAreIndependent(t *testing.T) {
	g := New(1.15, 8, 5)
	feed(g, "a", 2*time.Millisecond, 8)
	feed(g, "b", 2*time.Millisecond, 8)
	for i := 0; i < 20 && !g.Tripped("a"); i++ {
		g.Observe("a", 20*time.Millisecond, false)
	}
	if !g.Tripped("a") {
		t.Fatal("target a should have tripped")
	}
	if g.Tripped("b") {
		t.Fatal("target b, still healthy, must not be affected by a")
	}
}

func TestConcurrentObserveIsSafe(t *testing.T) {
	g := New(1.15, 8, 5)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				g.Observe("plc", 2*time.Millisecond, false)
				g.Tripped("plc")
			}
		}()
	}
	wg.Wait()
}
