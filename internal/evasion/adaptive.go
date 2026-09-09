package evasion

import (
	"math"
	"math/rand"
	"time"
)

type MLAdaptiveEngine struct {
	TrainingData       []ScanObservation
	DetectionThreshold float64
	AdaptationRate     float64
	RandomGenerator    *rand.Rand
	ModelWeights       []float64
}

type ScanObservation struct {
	PacketTiming  time.Duration
	PayloadSize   int
	FragmentCount int
	TTL           int
	SourceIP      string
	Detected      bool
	Timestamp     time.Time
}

func NewMLAdaptiveEngine(threshold float64, rate float64) *MLAdaptiveEngine {
	return &MLAdaptiveEngine{
		TrainingData:       []ScanObservation{},
		DetectionThreshold: threshold,
		AdaptationRate:     rate,
		RandomGenerator:    rand.New(rand.NewSource(time.Now().UnixNano())),
		ModelWeights:       []float64{0.25, 0.25, 0.25, 0.25},
	}
}

func (mae *MLAdaptiveEngine) PredictDetection(observation ScanObservation) float64 {

	inputs := []float64{
		normalizeTimingFeature(observation.PacketTiming),
		normalizePayloadFeature(observation.PayloadSize),
		normalizeFragmentFeature(observation.FragmentCount),
		normalizeTTLFeature(observation.TTL),
	}

	prediction := 0.0
	for i, input := range inputs {
		if i < len(mae.ModelWeights) {
			prediction += input * mae.ModelWeights[i]
		}
	}

	return 1.0 / (1.0 + math.Exp(-prediction))
}

func (mae *MLAdaptiveEngine) AdaptParameters(currentPattern ScanObservation) ScanObservation {
	pred := mae.PredictDetection(currentPattern)

	if pred > mae.DetectionThreshold {

		adapted := currentPattern

		adapted.PacketTiming += time.Duration(
			int(float64(adapted.PacketTiming) * 0.5),
		)

		adapted.FragmentCount++

		adapted.TTL = 64 + mae.RandomGenerator.Intn(64)

		return adapted
	}

	return currentPattern
}

func (mae *MLAdaptiveEngine) TrainModel(observations []ScanObservation) {
	if len(observations) == 0 {
		return
	}

	mae.TrainingData = append(mae.TrainingData, observations...)

	for _, obs := range observations {
		pred := mae.PredictDetection(obs)

		expected := 0.0
		if obs.Detected {
			expected = 1.0
		}
		error := expected - pred

		if error != 0 {
			inputs := []float64{
				normalizeTimingFeature(obs.PacketTiming),
				normalizePayloadFeature(obs.PayloadSize),
				normalizeFragmentFeature(obs.FragmentCount),
				normalizeTTLFeature(obs.TTL),
			}

			for i := 0; i < len(mae.ModelWeights) && i < len(inputs); i++ {
				mae.ModelWeights[i] += mae.AdaptationRate * error * inputs[i]

				if mae.ModelWeights[i] > 1.0 {
					mae.ModelWeights[i] = 1.0
				}
				if mae.ModelWeights[i] < 0.0 {
					mae.ModelWeights[i] = 0.0
				}
			}
		}
	}
}

func (mae *MLAdaptiveEngine) GetHighRiskPatterns() []ScanObservation {
	riskPatterns := []ScanObservation{}

	for _, obs := range mae.TrainingData {
		if obs.Detected {
			riskPatterns = append(riskPatterns, obs)
		}
	}

	return riskPatterns
}

func (mae *MLAdaptiveEngine) GetSafePatterns() []ScanObservation {
	safePatterns := []ScanObservation{}

	for _, obs := range mae.TrainingData {
		if !obs.Detected {
			pred := mae.PredictDetection(obs)
			if pred < mae.DetectionThreshold {
				safePatterns = append(safePatterns, obs)
			}
		}
	}

	return safePatterns
}

type BanditOptimization struct {
	Arms            []EvasionStrategy
	Rewards         []float64
	Attempts        []int
	ExplorationRate float64
	RandomGenerator *rand.Rand
}

type EvasionStrategy struct {
	Name       string
	Parameters map[string]interface{}
}

func (bo *BanditOptimization) SelectBestArm() *EvasionStrategy {
	if bo.RandomGenerator.Float64() < bo.ExplorationRate {

		idx := bo.RandomGenerator.Intn(len(bo.Arms))
		return &bo.Arms[idx]
	}

	bestIdx := 0
	bestReward := bo.Rewards[0]

	for i := 1; i < len(bo.Rewards); i++ {
		if bo.Rewards[i] > bestReward {
			bestReward = bo.Rewards[i]
			bestIdx = i
		}
	}

	return &bo.Arms[bestIdx]
}

func (bo *BanditOptimization) UpdateReward(armIdx int, reward float64) {
	if armIdx < len(bo.Rewards) {
		bo.Attempts[armIdx]++

		bo.Rewards[armIdx] = (bo.Rewards[armIdx]*float64(bo.Attempts[armIdx]-1) + reward) / float64(bo.Attempts[armIdx])
	}
}

func normalizeTimingFeature(timing time.Duration) float64 {
	ms := float64(timing.Milliseconds())
	return ms / 1000.0
}

func normalizePayloadFeature(size int) float64 {
	return float64(size) / 1000.0
}

func normalizeFragmentFeature(count int) float64 {
	return float64(count) / 10.0
}

func normalizeTTLFeature(ttl int) float64 {
	return float64(ttl) / 255.0
}

type BehavioralMimicryEngine struct {
	BrowserProfile      string
	UserAgentRotation   bool
	CookieHandling      bool
	JavaScriptExecution bool
	RandomGenerator     *rand.Rand
}

func NewBehavioralMimicryEngine() *BehavioralMimicryEngine {
	return &BehavioralMimicryEngine{
		BrowserProfile:      "Chrome",
		UserAgentRotation:   true,
		CookieHandling:      true,
		JavaScriptExecution: false,
		RandomGenerator:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (bme *BehavioralMimicryEngine) GetRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
	}

	if !bme.UserAgentRotation {
		return userAgents[0]
	}

	return userAgents[bme.RandomGenerator.Intn(len(userAgents))]
}

func (bme *BehavioralMimicryEngine) GetRealisticHeaders() map[string]string {
	return map[string]string{
		"User-Agent":                bme.GetRandomUserAgent(),
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Accept-Language":           "en-US,en;q=0.5",
		"Accept-Encoding":           "gzip, deflate",
		"DNT":                       "1",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
	}
}

func (bme *BehavioralMimicryEngine) SimulateHumanBehavior() time.Duration {

	return time.Duration(bme.RandomGenerator.Intn(900)+100) * time.Millisecond
}
