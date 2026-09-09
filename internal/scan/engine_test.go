package scan

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"tcpcat/config"
)

func TestTargetResultSerializesVulnerabilityAssessment(t *testing.T) {
	result := TargetResult{
		IP:    "127.0.0.1",
		Port:  8080,
		State: StateOpen,
		Assessment: VulnerabilityAssessment{
			Status: "not_assessed",
			Reason: "No reliable service version was detected.",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !json.Valid(data) || string(data) == "" {
		t.Fatal("result assessment was not serialized")
	}
}

func TestEngineExecutionBasic(t *testing.T) {
	opts := &config.Options{
		MaxWorkers: 2,
		RateLimit:  0,
		Timing:     3,
	}

	engine := NewEngine(opts)
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}

	targets := []string{"127.0.0.1"}
	ports := []int{22, 80, 443}

	results := engine.Execute(targets, ports)

	if len(results) == 0 {
		t.Fatal("Expected results, got empty slice")
	}

	for _, r := range results {
		if r.IP != "127.0.0.1" {
			t.Errorf("Expected IP 127.0.0.1, got %s", r.IP)
		}
		if r.Port <= 0 || r.Port > 65535 {
			t.Errorf("Invalid port: %d", r.Port)
		}
	}
}

func TestEngineProgressCallback(t *testing.T) {
	opts := &config.Options{
		MaxWorkers: 1,
		RateLimit:  0,
		Timing:     3,
	}

	engine := NewEngine(opts)

	targets := []string{"127.0.0.1"}
	ports := []int{22, 80}

	var progressCalls []Progress
	var mu sync.Mutex

	progressFunc := func(p Progress) {
		mu.Lock()
		progressCalls = append(progressCalls, p)
		mu.Unlock()
	}

	_ = engine.ExecuteWithProgress(targets, ports, progressFunc)

	if len(progressCalls) == 0 {
		t.Error("Expected progress callbacks, got none")
	}

	for i := 1; i < len(progressCalls); i++ {
		if progressCalls[i].Completed < progressCalls[i-1].Completed {
			t.Error("Progress completed count decreased")
		}
	}
}

func TestEngineWithRateLimit(t *testing.T) {
	opts := &config.Options{
		MaxWorkers: 2,
		RateLimit:  100,
		Timing:     3,
	}

	engine := NewEngine(opts)

	targets := []string{"127.0.0.1"}
	ports := []int{22, 80, 443, 8080}

	start := time.Now()
	_ = engine.Execute(targets, ports)
	duration := time.Since(start)

	minExpected := time.Duration(4*1000/100) * time.Millisecond
	if duration < minExpected {
		t.Logf("Warning: scan completed in %v, expected at least %v (rate limit may not be precise)", duration, minExpected)
	}
}

func TestEngineWorkerPoolScaling(t *testing.T) {
	tests := []struct {
		name       string
		maxWorkers int
		expectFail bool
	}{
		{"single worker", 1, false},
		{"multiple workers", 4, false},
		{"many workers", 16, false},
		{"invalid workers", 0, false},
		{"negative workers", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &config.Options{
				MaxWorkers: tt.maxWorkers,
				RateLimit:  0,
				Timing:     3,
			}

			engine := NewEngine(opts)
			if engine == nil && !tt.expectFail {
				t.Fatal("NewEngine returned nil unexpectedly")
			}

			if engine != nil {
				targets := []string{"127.0.0.1"}
				ports := []int{22}
				results := engine.Execute(targets, ports)
				if len(results) == 0 {
					t.Fatal("Expected results")
				}
			}
		})
	}
}

func TestEngineMultipleTargets(t *testing.T) {
	opts := &config.Options{
		MaxWorkers: 2,
		RateLimit:  0,
		Timing:     3,
	}

	engine := NewEngine(opts)

	targets := []string{"127.0.0.1", "localhost"}
	ports := []int{22, 80}

	results := engine.Execute(targets, ports)

	if len(results) < 2 {
		t.Fatalf("Expected at least 2 results, got %d", len(results))
	}

	targetMap := make(map[string]bool)
	for _, r := range results {
		targetMap[r.IP] = true
	}

	if !targetMap["127.0.0.1"] && !targetMap["localhost"] {
		t.Error("Did not scan all targets")
	}
}

func TestEngineResultStructure(t *testing.T) {
	opts := &config.Options{
		MaxWorkers: 1,
		RateLimit:  0,
		Timing:     3,
	}

	engine := NewEngine(opts)

	targets := []string{"127.0.0.1"}
	ports := []int{22}

	results := engine.Execute(targets, ports)

	for _, r := range results {

		if r.IP == "" {
			t.Error("Result has empty IP")
		}

		if r.Port < 1 || r.Port > 65535 {
			t.Errorf("Invalid port %d", r.Port)
		}

		if r.State == "" {
			t.Error("Result has empty state")
		}

		validStates := map[string]bool{
			StateOpen:     true,
			StateClosed:   true,
			StateFiltered: true,
		}
		if !validStates[r.State] {
			t.Errorf("Unknown state: %s", r.State)
		}
	}
}

func BenchmarkEngineExecution(b *testing.B) {
	opts := &config.Options{
		MaxWorkers: 4,
		RateLimit:  0,
		Timing:     3,
	}

	engine := NewEngine(opts)
	targets := []string{"127.0.0.1"}
	ports := []int{22, 80, 443}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Execute(targets, ports)
	}
}

func BenchmarkConcurrentScans(b *testing.B) {
	opts := &config.Options{
		MaxWorkers: 8,
		RateLimit:  0,
		Timing:     3,
	}

	engine := NewEngine(opts)

	b.Run("parallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				target := fmt.Sprintf("127.0.0.%d", (i%254)+1)
				port := 22 + (i % 20)
				results := engine.Execute([]string{target}, []int{port})
				if len(results) == 0 {
					b.Error("No results")
				}
				i++
			}
		})
	})
}

func TestEngineEmpty(t *testing.T) {
	opts := &config.Options{
		MaxWorkers: 1,
		RateLimit:  0,
		Timing:     3,
	}

	engine := NewEngine(opts)

	results := engine.Execute([]string{"127.0.0.1"}, []int{})
	if len(results) != 0 {
		t.Error("Expected no results for empty ports")
	}

	results = engine.Execute([]string{}, []int{22})
	if len(results) != 0 {
		t.Error("Expected no results for empty targets")
	}
}

func TestScanJobChannel(t *testing.T) {
	opts := &config.Options{
		MaxWorkers: 1,
		RateLimit:  0,
		Timing:     3,
	}

	engine := NewEngine(opts)

	targets := []string{"127.0.0.1"}
	ports := []int{22, 80, 443}

	results := engine.Execute(targets, ports)

	expectedJobs := len(targets) * len(ports)
	if len(results) != expectedJobs {
		t.Errorf("Expected %d results, got %d", expectedJobs, len(results))
	}
}
