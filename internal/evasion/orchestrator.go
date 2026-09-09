package evasion

import (
	"math/rand"
	"net"
	"time"
)

type EvasionOrchestrator struct {
	Timing        *AdaptiveJitterEngine
	Fragmentation *FragmentationEngine
	Decoy         *DecoySwarmEngine
	Protocol      *ProtocolEvasion
	MLAdapter     *MLAdaptiveEngine
	Behavioral    *BehavioralMimicryEngine
	Enabled       bool
	CurrentMode   EvasionMode
}

type EvasionMode int

const (
	EvasionModeOff EvasionMode = iota
	EvasionModeLight
	EvasionModeModerate
	EvasionModeAggressive
	EvasionModeStealthy
	EvasionModeAdaptive
)

func NewEvasionOrchestrator(
	realIP net.IP,
	decoyIPs []net.IP,
	baseRate time.Duration,
) *EvasionOrchestrator {
	return &EvasionOrchestrator{
		Timing:        NewAdaptiveJitterEngine(baseRate, 0.3),
		Fragmentation: NewFragmentationEngine(1500),
		Decoy:         NewDecoySwarmEngine(realIP, decoyIPs),
		Protocol:      NewProtocolEvasion(),
		MLAdapter:     NewMLAdaptiveEngine(0.6, 0.1),
		Behavioral:    NewBehavioralMimicryEngine(),
		Enabled:       false,
		CurrentMode:   EvasionModeOff,
	}
}

func (eo *EvasionOrchestrator) Configure(mode EvasionMode) {
	eo.CurrentMode = mode

	switch mode {
	case EvasionModeLight:

		eo.Timing.ApplyTimingPattern(PatternNormal)
		eo.Fragmentation.OverlapStrategy = "sequential"
		eo.Decoy.Pattern = "rotate"
		eo.Protocol.TCPWindowStrategy = "normal"
		eo.Enabled = true

	case EvasionModeModerate:

		eo.Timing.ApplyTimingPattern(PatternPolite)
		eo.Fragmentation.OverlapStrategy = "sequential"
		eo.Fragmentation.DecoyFragments = 2
		eo.Decoy.Pattern = "random"
		eo.Protocol.TCPWindowStrategy = "random"
		eo.Enabled = true

	case EvasionModeAggressive:

		eo.Timing.ApplyTimingPattern(PatternAggressive)
		eo.Fragmentation.OverlapStrategy = "overlap"
		eo.Fragmentation.DecoyFragments = 5
		eo.Decoy.Pattern = "staggered"
		eo.Protocol.TCPWindowStrategy = "fragmented"
		eo.Enabled = true

	case EvasionModeStealthy:

		eo.Timing.ApplyTimingPattern(PatternSneaky)
		eo.Fragmentation.OverlapStrategy = "gaps"
		eo.Fragmentation.DecoyFragments = 10
		eo.Decoy.Pattern = "burst"
		eo.Protocol.TCPWindowStrategy = "zero-window"
		eo.Enabled = true

	case EvasionModeAdaptive:

		eo.Timing.ApplyTimingPattern(PatternAdaptive)
		eo.Fragmentation.OverlapStrategy = "gaps"
		eo.Decoy.Pattern = "random"
		eo.MLAdapter.DetectionThreshold = 0.5
		eo.Enabled = true

	default:
		eo.Enabled = false
	}
}

func (eo *EvasionOrchestrator) ExecuteStealth(
	targetIP string,
	ports []uint16,
	scanType string,
) EvasionReport {
	report := EvasionReport{
		StartTime:         time.Now(),
		TargetIP:          targetIP,
		PortCount:         len(ports),
		ScanType:          scanType,
		EvasionMode:       eo.CurrentMode,
		TechniquesApplied: []string{},
	}

	if !eo.Enabled {
		report.Status = "Evasion disabled"
		return report
	}

	observation := ScanObservation{
		PacketTiming:  eo.Timing.BaseInterval,
		PayloadSize:   64,
		FragmentCount: 0,
		TTL:           64,
		SourceIP:      eo.Decoy.RealIP.String(),
		Timestamp:     time.Now(),
	}

	risk := eo.MLAdapter.PredictDetection(observation)
	report.DetectionRisk = risk

	if risk > 0.7 {

		schedule := eo.Timing.GeneratePacketSchedule(len(ports))
		report.TechniquesApplied = append(report.TechniquesApplied, "Adaptive Jitter")

		if len(ports) > 0 {
			fragment := eo.Fragmentation.FragmentPacket(
				[]byte(scanType),
				net.ParseIP(targetIP),
				uint16(rand.Intn(65535)),
			)
			report.FragmentCount = len(fragment)
			report.TechniquesApplied = append(report.TechniquesApplied, "Advanced Fragmentation")
		}

		decoys := eo.Decoy.GenerateDecoyPattern(len(ports), ports)
		report.DecoyCount = len(decoys)
		report.TechniquesApplied = append(report.TechniquesApplied, "Decoy Swarm")

		_ = eo.Behavioral.GetRandomUserAgent()
		report.TechniquesApplied = append(report.TechniquesApplied, "Behavioral Mimicry")

		report.TechniquesApplied = append(report.TechniquesApplied, "Protocol Evasion")

		_ = schedule
	} else {
		report.TechniquesApplied = append(report.TechniquesApplied, "Normal scan")
	}

	report.EndTime = time.Now()
	report.Status = "Scan completed"

	return report
}

type EvasionReport struct {
	StartTime         time.Time
	EndTime           time.Time
	TargetIP          string
	PortCount         int
	ScanType          string
	EvasionMode       EvasionMode
	TechniquesApplied []string
	FragmentCount     int
	DecoyCount        int
	DetectionRisk     float64
	Status            string
}

func (eo *EvasionOrchestrator) TrainWithResults(
	observations []ScanObservation,
) {
	if eo.MLAdapter != nil {
		eo.MLAdapter.TrainModel(observations)
	}
}

func (eo *EvasionOrchestrator) GetEvasionStats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["enabled"] = eo.Enabled
	stats["mode"] = eo.CurrentMode
	stats["timing_interval"] = eo.Timing.BaseInterval.String()
	stats["jitter_factor"] = eo.Timing.JitterFactor
	stats["decoy_count"] = len(eo.Decoy.DecoyIPs)
	stats["fragmentation_enabled"] = eo.Fragmentation.OverlapStrategy != "sequential"
	stats["ml_threshold"] = eo.MLAdapter.DetectionThreshold

	return stats
}

func (eo *EvasionOrchestrator) SetDetectionRisk(risk float64) {
	if risk > 0.8 {
		eo.Configure(EvasionModeStealthy)
	} else if risk > 0.6 {
		eo.Configure(EvasionModeAggressive)
	} else if risk > 0.4 {
		eo.Configure(EvasionModeModerate)
	} else {
		eo.Configure(EvasionModeLight)
	}
}

func (eo *EvasionOrchestrator) Reset() {
	eo.MLAdapter.TrainingData = []ScanObservation{}
	eo.Enabled = false
	eo.CurrentMode = EvasionModeOff
}
