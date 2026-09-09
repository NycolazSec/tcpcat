package evasion

import (
	"net"
	"testing"
	"time"
)

func TestAdaptiveJitterEngine(t *testing.T) {
	engine := NewAdaptiveJitterEngine(100*time.Millisecond, 0.3)

	tests := []struct {
		name      string
		packets   int
		expectMin int
	}{
		{"Small schedule", 5, 1},
		{"Large schedule", 1000, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schedule := engine.GeneratePacketSchedule(tt.packets)
			if len(schedule) != tt.packets {
				t.Errorf("Expected %d packets, got %d", tt.packets, len(schedule))
			}

			for _, duration := range schedule {
				if duration < 1*time.Millisecond {
					t.Errorf("Duration too small: %v", duration)
				}
			}
		})
	}
}

func TestFragmentationEngine(t *testing.T) {
	engine := NewFragmentationEngine(1500)
	payload := []byte("test payload for fragmentation")
	dstIP := net.ParseIP("192.168.1.1")

	fragments := engine.FragmentPacket(payload, dstIP, 1234)

	if len(fragments) == 0 {
		t.Error("Expected at least one fragment")
	}

	totalSize := 0
	for _, frag := range fragments {
		totalSize += len(frag.Data)
	}

	if totalSize < len(payload) {
		t.Errorf("Fragment data size %d less than payload %d", totalSize, len(payload))
	}
}

func TestDecoySwarmEngine(t *testing.T) {
	realIP := net.ParseIP("192.168.1.10")
	decoyIPs := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		net.ParseIP("192.168.1.3"),
	}

	engine := NewDecoySwarmEngine(realIP, decoyIPs)
	ports := []uint16{22, 80, 443}

	pattern := engine.GenerateDecoyPattern(10, ports)

	if len(pattern) != 10 {
		t.Errorf("Expected 10 decoy packets, got %d", len(pattern))
	}

	for _, packet := range pattern {
		if packet.ReplyIP.String() != realIP.String() {
			t.Errorf("Expected reply IP %s, got %s", realIP.String(), packet.ReplyIP.String())
		}

		if packet.SourceIP.String() == realIP.String() {
			t.Errorf("Decoy packet should not use real IP")
		}
	}
}

func TestProtocolEvasion(t *testing.T) {
	engine := NewProtocolEvasion()

	tests := []struct {
		name     string
		strategy string
		fn       func() uint16
	}{
		{"Normal window", "normal", func() uint16 { return 65535 }},
		{"Zero window", "zero-window", engine.TCPWindowEvasion},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine.TCPWindowStrategy = tt.strategy
			window := engine.TCPWindowEvasion()
			if window == 0 && tt.strategy != "zero-window" {
				t.Errorf("Unexpected zero window for strategy %s", tt.strategy)
			}
		})
	}
}

func TestMLAdaptiveEngine(t *testing.T) {
	engine := NewMLAdaptiveEngine(0.6, 0.1)

	observation := ScanObservation{
		PacketTiming:  100 * time.Millisecond,
		PayloadSize:   64,
		FragmentCount: 0,
		TTL:           64,
		SourceIP:      "192.168.1.1",
		Detected:      false,
		Timestamp:     time.Now(),
	}

	pred := engine.PredictDetection(observation)
	if pred < 0 || pred > 1 {
		t.Errorf("Prediction should be between 0 and 1, got %f", pred)
	}

	_ = engine.AdaptParameters(observation)

	observations := []ScanObservation{observation}
	engine.TrainModel(observations)

	if len(engine.TrainingData) == 0 {
		t.Error("Training data should be populated")
	}
}

func TestBehavioralMimicryEngine(t *testing.T) {
	engine := NewBehavioralMimicryEngine()

	userAgent := engine.GetRandomUserAgent()
	if userAgent == "" {
		t.Error("User agent should not be empty")
	}

	headers := engine.GetRealisticHeaders()
	if len(headers) == 0 {
		t.Error("Headers should not be empty")
	}

	if _, ok := headers["User-Agent"]; !ok {
		t.Error("Headers should contain User-Agent")
	}

	delay := engine.SimulateHumanBehavior()
	if delay < 100*time.Millisecond || delay > 1*time.Second {
		t.Errorf("Delay out of range: %v", delay)
	}
}

func TestEvasionOrchestrator(t *testing.T) {
	realIP := net.ParseIP("192.168.1.10")
	decoyIPs := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
	}

	orch := NewEvasionOrchestrator(realIP, decoyIPs, 100*time.Millisecond)

	tests := []struct {
		name string
		mode EvasionMode
	}{
		{"Off", EvasionModeOff},
		{"Light", EvasionModeLight},
		{"Moderate", EvasionModeModerate},
		{"Aggressive", EvasionModeAggressive},
		{"Stealthy", EvasionModeStealthy},
		{"Adaptive", EvasionModeAdaptive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch.Configure(tt.mode)

			if tt.mode == EvasionModeOff {
				if orch.Enabled {
					t.Error("Evasion should be disabled in Off mode")
				}
			} else {
				if !orch.Enabled {
					t.Error("Evasion should be enabled")
				}
			}
		})
	}

	orch.Configure(EvasionModeModerate)
	ports := []uint16{22, 80, 443}
	report := orch.ExecuteStealth("192.168.1.50", ports, "SYN")

	if report.TargetIP != "192.168.1.50" {
		t.Errorf("Expected target IP 192.168.1.50, got %s", report.TargetIP)
	}

	if report.PortCount != len(ports) {
		t.Errorf("Expected %d ports, got %d", len(ports), report.PortCount)
	}

	if len(report.TechniquesApplied) == 0 {
		t.Error("No evasion techniques were applied")
	}
}

func TestEvasionStats(t *testing.T) {
	realIP := net.ParseIP("192.168.1.10")
	orch := NewEvasionOrchestrator(realIP, []net.IP{}, 100*time.Millisecond)

	orch.Configure(EvasionModeModerate)
	stats := orch.GetEvasionStats()

	if stats["enabled"] != true {
		t.Error("Evasion should be enabled in stats")
	}

	if _, ok := stats["decoy_count"]; !ok {
		t.Error("Stats should contain decoy_count")
	}
}

func BenchmarkAdaptiveJitter(b *testing.B) {
	engine := NewAdaptiveJitterEngine(100*time.Millisecond, 0.3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.GeneratePacketSchedule(1000)
	}
}

func BenchmarkFragmentation(b *testing.B) {
	engine := NewFragmentationEngine(1500)
	payload := []byte("test payload for fragmentation")
	dstIP := net.ParseIP("192.168.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.FragmentPacket(payload, dstIP, uint16(i))
	}
}

func BenchmarkMLPrediction(b *testing.B) {
	engine := NewMLAdaptiveEngine(0.6, 0.1)
	observation := ScanObservation{
		PacketTiming:  100 * time.Millisecond,
		PayloadSize:   64,
		FragmentCount: 0,
		TTL:           64,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.PredictDetection(observation)
	}
}
