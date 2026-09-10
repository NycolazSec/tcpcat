package scan

import (
	"sync"
	"testing"
	"time"
)

func TestRTTEstimatorConverges(t *testing.T) {
	r := NewRTTEstimator()
	for i := 0; i < 50; i++ {
		r.Sample(20 * time.Millisecond)
	}
	got := r.SRTT()
	if got < 18*time.Millisecond || got > 22*time.Millisecond {
		t.Fatalf("SRTT did not converge to ~20ms, got %v", got)
	}
}

func TestRTTEstimatorIgnoresNonPositiveSamples(t *testing.T) {
	r := NewRTTEstimator()
	r.Sample(0)
	r.Sample(-5 * time.Millisecond)
	if r.SRTT() != 0 {
		t.Fatalf("expected SRTT to remain 0, got %v", r.SRTT())
	}
}

func TestRTTEstimatorRTOHasFloor(t *testing.T) {
	r := NewRTTEstimator()
	if got := r.RTO(100 * time.Millisecond); got != 100*time.Millisecond {
		t.Fatalf("expected RTO floor of 100ms with no samples, got %v", got)
	}
}

func TestAdaptiveRateLimiterIncreasesOnLowLoss(t *testing.T) {
	rl := NewAdaptiveRateLimiter(1000, 100, 10000)
	for i := 0; i < windowSize; i++ {
		rl.Report(false) // no losses at all
	}
	if got := rl.CurrentRate(); got <= 1000 {
		t.Fatalf("expected rate to increase above 1000pps, got %d", got)
	}
}

func TestAdaptiveRateLimiterBacksOffOnHighLoss(t *testing.T) {
	rl := NewAdaptiveRateLimiter(1000, 100, 10000)
	for i := 0; i < windowSize; i++ {
		rl.Report(true) // 100% loss
	}
	if got := rl.CurrentRate(); got != 500 {
		t.Fatalf("expected rate to halve to 500pps, got %d", got)
	}
}

func TestAdaptiveRateLimiterRespectsBounds(t *testing.T) {
	rl := NewAdaptiveRateLimiter(100, 100, 200)
	for round := 0; round < 20; round++ {
		for i := 0; i < windowSize; i++ {
			rl.Report(false)
		}
	}
	if got := rl.CurrentRate(); got > 200 {
		t.Fatalf("rate exceeded max bound: %d", got)
	}

	rl2 := NewAdaptiveRateLimiter(200, 100, 200)
	for round := 0; round < 20; round++ {
		for i := 0; i < windowSize; i++ {
			rl2.Report(true)
		}
	}
	if got := rl2.CurrentRate(); got < 100 {
		t.Fatalf("rate dropped below min bound: %d", got)
	}
}

func TestAdaptiveRateLimiterConcurrentReportIsRaceFree(t *testing.T) {
	rl := NewAdaptiveRateLimiter(500, 100, 5000)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				rl.Report(i%10 == 0)
			}
		}()
	}
	wg.Wait()
	if rate := rl.CurrentRate(); rate < 100 || rate > 5000 {
		t.Fatalf("rate escaped bounds under concurrent load: %d", rate)
	}
}

func TestAdaptiveRateLimiterWaitPaces(t *testing.T) {
	rl := NewAdaptiveRateLimiter(1000, 100, 10000) // ~1ms between slots
	start := time.Now()
	for i := 0; i < 5; i++ {
		rl.Wait()
	}
	elapsed := time.Since(start)
	if elapsed < 3*time.Millisecond {
		t.Fatalf("Wait did not pace calls, elapsed=%v for 5 slots at 1000pps", elapsed)
	}
}
