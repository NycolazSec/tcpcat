package scan

import (
	"testing"
	"time"

	"tcpcat/config"
)

func TestProbeAttempts(t *testing.T) {
	tests := []struct {
		name string
		opts *config.Options
		want int
	}{
		{"nil opts uses default of 2 retries", nil, 3},
		{"explicit retries", &config.Options{MaxRetries: 5}, 6},
		{"zero retries disables retrying", &config.Options{MaxRetries: 0}, 1},
		{"negative falls back to default", &config.Options{MaxRetries: -1}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := probeAttempts(tt.opts); got != tt.want {
				t.Errorf("probeAttempts(%+v) = %d, want %d", tt.opts, got, tt.want)
			}
		})
	}
}

func TestProbeTimeoutFallsBackWithoutSamples(t *testing.T) {
	fallback := 500 * time.Millisecond

	if got := probeTimeout(nil, fallback); got != fallback {
		t.Errorf("probeTimeout(nil, ...) = %v, want %v", got, fallback)
	}

	rtt := NewRTTEstimator()
	if got := probeTimeout(rtt, fallback); got != fallback {
		t.Errorf("probeTimeout(unseeded estimator) = %v, want fallback %v", got, fallback)
	}
}

func TestProbeTimeoutUsesRTOOnceSeeded(t *testing.T) {
	fallback := 500 * time.Millisecond
	rtt := NewRTTEstimator()
	rtt.Sample(20 * time.Millisecond)

	got := probeTimeout(rtt, fallback)
	want := rtt.RTO(fallback / 4)
	if got != want {
		t.Errorf("probeTimeout(seeded estimator) = %v, want %v", got, want)
	}
	// A fast, healthy target's RTO should resolve well inside the
	// original fixed timeout, which is the whole point of wiring RTO in.
	if got >= fallback {
		t.Errorf("probeTimeout() = %v, expected it to be shorter than the %v fallback for a 20ms RTT", got, fallback)
	}
}

func TestRTTEstimatorHasSamples(t *testing.T) {
	rtt := NewRTTEstimator()
	if rtt.HasSamples() {
		t.Error("HasSamples() = true before any Sample() call")
	}
	rtt.Sample(10 * time.Millisecond)
	if !rtt.HasSamples() {
		t.Error("HasSamples() = false after a Sample() call")
	}
}
