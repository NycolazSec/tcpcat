package scan

import (
	"net"
	"time"

	"tcpcat/internal/evasion"
)

type EvasionOptions struct {
	Mode            evasion.EvasionMode
	Enabled         bool
	Decoys          []net.IP
	TimingJitter    float64
	FragmentPackets bool
	UseAdaptiveML   bool
}

type EngineWithEvasion struct {
	*Engine
	evasionOrch *evasion.EvasionOrchestrator
	evasionOpts EvasionOptions
}

func NewEngineWithEvasion(engine *Engine, opts EvasionOptions) *EngineWithEvasion {
	realIP := net.ParseIP("127.0.0.1")
	evasionOrch := evasion.NewEvasionOrchestrator(realIP, opts.Decoys, 100*time.Millisecond)

	if opts.Enabled {
		evasionOrch.Configure(opts.Mode)
	}

	return &EngineWithEvasion{
		Engine:      engine,
		evasionOrch: evasionOrch,
		evasionOpts: opts,
	}
}

func (e *EngineWithEvasion) ExecuteWithEvasion(
	targets []string,
	ports []int,
	onProgress ProgressFunc,
) ([]TargetResult, *evasion.EvasionReport) {

	results := e.ExecuteWithProgress(targets, ports, onProgress)

	ports16 := make([]uint16, len(ports))
	for i, p := range ports {
		ports16[i] = uint16(p)
	}

	if len(targets) > 0 {
		report := e.evasionOrch.ExecuteStealth(targets[0], ports16, "SYN")
		return results, &report
	}

	return results, nil
}

func (e *EngineWithEvasion) GetEvasionStats() map[string]interface{} {
	return e.evasionOrch.GetEvasionStats()
}

func (e *EngineWithEvasion) UpdateEvasionMode(mode evasion.EvasionMode) {
	e.evasionOrch.Configure(mode)
	e.evasionOpts.Mode = mode
}

func (e *EngineWithEvasion) SetDetectionRisk(risk float64) {
	e.evasionOrch.SetDetectionRisk(risk)
}

func (e *EngineWithEvasion) DisableEvasion() {
	e.evasionOrch.Enabled = false
	e.evasionOpts.Enabled = false
}

func (e *EngineWithEvasion) EnableEvasion() {
	if e.evasionOpts.Enabled {
		e.evasionOrch.Configure(e.evasionOpts.Mode)
	}
}

func (e *EngineWithEvasion) TrainEvasionModel(observations []evasion.ScanObservation) {
	e.evasionOrch.TrainWithResults(observations)
}
