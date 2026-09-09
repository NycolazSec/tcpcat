package evasion

import (
	"math"
	"math/rand"
	"time"
)

type AdaptiveJitterEngine struct {
	BaseInterval    time.Duration
	JitterFactor    float64
	BurstSize       int
	BurstPause      time.Duration
	AdaptiveMode    bool
	DetectionProbe  chan bool
	RandomGenerator *rand.Rand
}

func NewAdaptiveJitterEngine(baseInterval time.Duration, jitterFactor float64) *AdaptiveJitterEngine {
	return &AdaptiveJitterEngine{
		BaseInterval:    baseInterval,
		JitterFactor:    jitterFactor,
		BurstSize:       rand.Intn(15) + 5,
		BurstPause:      time.Duration(rand.Intn(500)+100) * time.Millisecond,
		AdaptiveMode:    false,
		DetectionProbe:  make(chan bool, 1),
		RandomGenerator: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (aje *AdaptiveJitterEngine) GeneratePacketSchedule(totalPackets int) []time.Duration {
	schedule := make([]time.Duration, totalPackets)

	if !aje.AdaptiveMode {

		for i := 0; i < totalPackets; i++ {
			noise := aje.RandomGenerator.NormFloat64() * aje.JitterFactor
			interval := time.Duration(
				int64(float64(aje.BaseInterval) * (1 + noise)),
			)
			if interval < 1*time.Millisecond {
				interval = 1 * time.Millisecond
			}
			schedule[i] = interval
		}
	} else {

		burstIdx := 0
		for i := 0; i < totalPackets; i++ {
			if burstIdx < aje.BurstSize {

				schedule[i] = aje.BaseInterval / 10
				burstIdx++
			} else {

				select {
				case detected := <-aje.DetectionProbe:
					if detected {

						schedule[i] = time.Duration(
							aje.RandomGenerator.Intn(5000)+1000,
						) * time.Millisecond
					} else {
						schedule[i] = aje.BaseInterval
					}
				default:
					schedule[i] = aje.BaseInterval
				}
				if burstIdx > aje.BurstSize {
					burstIdx = 0
					schedule[i] += aje.BurstPause
				}
			}
		}
	}

	return schedule
}

func (aje *AdaptiveJitterEngine) GaussianJitter(baseInterval time.Duration) time.Duration {
	noise := math.Abs(aje.RandomGenerator.NormFloat64()) * aje.JitterFactor
	jittered := time.Duration(float64(baseInterval) * (1 + noise))
	return jittered
}

func (aje *AdaptiveJitterEngine) ExponentialBackoff(attempt int) time.Duration {
	backoff := time.Duration(math.Pow(2, float64(attempt))) * aje.BaseInterval
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	return backoff
}

func (aje *AdaptiveJitterEngine) BurstPattern(burstCount, packetsPerBurst int) []time.Duration {
	schedule := make([]time.Duration, burstCount*packetsPerBurst)
	scheduleIdx := 0

	for burst := 0; burst < burstCount; burst++ {

		for p := 0; p < packetsPerBurst; p++ {
			schedule[scheduleIdx] = aje.BaseInterval / time.Duration(packetsPerBurst)
			scheduleIdx++
		}

		if burst < burstCount-1 {
			for p := 0; p < packetsPerBurst; p++ {
				schedule[scheduleIdx] = aje.BurstPause
				scheduleIdx++
			}
		}
	}

	return schedule[:scheduleIdx]
}

func (aje *AdaptiveJitterEngine) ProbeIDS(targetIP string, portProbe int) bool {

	return false
}

type TimingPattern int

const (
	PatternNormal TimingPattern = iota
	PatternSneaky
	PatternAggressive
	PatternPolite
	PatternAdaptive
)

func (aje *AdaptiveJitterEngine) ApplyTimingPattern(pattern TimingPattern) {
	switch pattern {
	case PatternSneaky:
		aje.JitterFactor = 0.8
		aje.BurstSize = 3
		aje.BurstPause = 2 * time.Second

	case PatternAggressive:
		aje.JitterFactor = 0.1
		aje.BurstSize = 50
		aje.BurstPause = 100 * time.Millisecond

	case PatternPolite:
		aje.JitterFactor = 0.5
		aje.BurstSize = 10
		aje.BurstPause = 1 * time.Second

	case PatternAdaptive:
		aje.AdaptiveMode = true

	default:
		aje.JitterFactor = 0.3
		aje.BurstSize = 20
		aje.BurstPause = 500 * time.Millisecond
	}
}
