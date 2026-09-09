package scan

import (
	"testing"
	"time"

	"tcpcat/config"
)

func TestBatchProcessing(t *testing.T) {
	opts := &config.Options{
		MaxWorkers: 4,
	}
	engine := NewEngine(opts)
	optEngine := NewOptimizedEngine(engine, 100, 1)

	targets := []ScanJob{
		{IP: "127.0.0.1", Port: 22},
		{IP: "127.0.0.1", Port: 80},
		{IP: "127.0.0.1", Port: 443},
		{IP: "127.0.0.1", Port: 3306},
		{IP: "127.0.0.1", Port: 5432},
	}

	results, err := optEngine.ScanBatch(targets)
	if err != nil {
		t.Errorf("Batch scan failed: %v", err)
	}

	if len(results) != len(targets) {
		t.Errorf("Expected %d results, got %d", len(targets), len(results))
	}
}

func TestCPUAffinity(t *testing.T) {
	opts := &config.Options{MaxWorkers: 4}
	engine := NewEngine(opts)
	optEngine := NewOptimizedEngine(engine, 100, 1)

	optEngine.SetCPUAffinity(8)

	if len(optEngine.WorkerAffinity) != 4 {
		t.Errorf("Expected 4 affinity mappings, got %d", len(optEngine.WorkerAffinity))
	}

	for i := 0; i < 4; i++ {
		if coreID, ok := optEngine.WorkerAffinity[i]; !ok {
			t.Errorf("Worker %d missing CPU affinity", i)
		} else if coreID < 0 || coreID >= 8 {
			t.Errorf("Invalid core ID %d for worker %d", coreID, i)
		}
	}
}

func TestNUMABuffer(t *testing.T) {
	buffer := NewNUMALocalBuffer(0, 10)

	result := TargetResult{
		IP:    "127.0.0.1",
		Port:  22,
		State: "OPEN",
	}

	if err := buffer.Append(result); err != nil {
		t.Errorf("Failed to append to NUMA buffer: %v", err)
	}

	results := buffer.Flush()
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	if results[0].IP != "127.0.0.1" {
		t.Errorf("Expected IP 127.0.0.1, got %s", results[0].IP)
	}
}

func TestHashMapOptimization(t *testing.T) {
	tests := []struct {
		targetCount int
		minEntries  uint32
	}{
		{100, 120},
		{1000, 1200},
		{10000, 12000},
		{100000, 120000},
	}

	for _, tt := range tests {
		config := OptimizeHashMap(tt.targetCount)

		if config.MaxEntries < tt.minEntries {
			t.Errorf("MaxEntries %d < minimum %d", config.MaxEntries, tt.minEntries)
		}

		if config.KeySize != 4 {
			t.Errorf("Expected KeySize 4, got %d", config.KeySize)
		}

		if config.ValueSize != 20 {
			t.Errorf("Expected ValueSize 20, got %d", config.ValueSize)
		}
	}
}

func TestPerformanceMetrics(t *testing.T) {
	opts := &config.Options{MaxWorkers: 2}
	engine := NewEngine(opts)
	optEngine := NewOptimizedEngine(engine, 50, 1)

	optEngine.stats.TotalScanned = 1000
	optEngine.stats.TotalOpen = 50
	optEngine.stats.TotalClosed = 950
	optEngine.stats.StartTime = time.Now().Add(-1 * time.Second)
	optEngine.stats.EndTime = time.Now()

	optEngine.computeStats()

	if optEngine.stats.ThroughputPps <= 0 {
		t.Errorf("Throughput should be positive, got %.0f", optEngine.stats.ThroughputPps)
	}

	if optEngine.stats.AvgLatency <= 0 {
		t.Errorf("AvgLatency should be positive, got %v", optEngine.stats.AvgLatency)
	}
}

func TestNUMABufferFull(t *testing.T) {
	buffer := NewNUMALocalBuffer(0, 2)

	results := []TargetResult{
		{IP: "127.0.0.1", Port: 22},
		{IP: "127.0.0.1", Port: 80},
		{IP: "127.0.0.1", Port: 443},
	}

	for i, result := range results {
		err := buffer.Append(result)
		if i < 2 && err != nil {
			t.Errorf("Failed to append result %d: %v", i, err)
		} else if i >= 2 && err == nil {
			t.Error("Expected error when buffer full")
		}
	}
}

func BenchmarkBatchProcessing(b *testing.B) {
	opts := &config.Options{MaxWorkers: 4}
	engine := NewEngine(opts)
	optEngine := NewOptimizedEngine(engine, 100, 1)

	targets := make([]ScanJob, 100)
	for i := 0; i < 100; i++ {
		targets[i] = ScanJob{IP: "127.0.0.1", Port: 22 + i%1000}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = optEngine.ScanBatch(targets)
	}
}

func BenchmarkNUMABuffer(b *testing.B) {
	buffer := NewNUMALocalBuffer(0, 1000)
	result := TargetResult{IP: "127.0.0.1", Port: 22}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buffer.Append(result)
		if i%1000 == 0 {
			buffer.Flush()
		}
	}
}
