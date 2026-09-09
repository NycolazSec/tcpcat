package scan

import (
	"tcpcat/config"
	"testing"
)

func TestFilteredPortsSkipServiceDetection(t *testing.T) {
	opts := &config.Options{
		ConnectScan:   true,
		ServiceDetect: true,
		Timing:        3,
		MaxWorkers:    2,
	}

	engine := NewEngine(opts)
	if engine == nil {
		t.Fatal("Failed to create engine")
	}

	results := engine.Execute([]string{"127.0.0.1"}, []int{22, 80, 443})

	for _, result := range results {

		if result.State == StateFiltered {
			if result.Service != "" && result.Service != "unknown" {
				t.Errorf("FILTERED port %d should not have service name, got %q",
					result.Port, result.Service)
			}
			if result.Version != "" {
				t.Errorf("FILTERED port %d should not have version info, got %q",
					result.Port, result.Version)
			}
		}

		if result.State == StateOpen {

			t.Logf("OPEN port %d has service=%q version=%q", result.Port, result.Service, result.Version)
		}
	}
}

func TestScanResultStateValidity(t *testing.T) {
	validStates := map[string]bool{
		StateOpen:         true,
		StateClosed:       true,
		StateFiltered:     true,
		StateOpenFiltered: true,
		StateUnfiltered:   true,
	}

	opts := &config.Options{
		ConnectScan: true,
		Timing:      3,
		MaxWorkers:  2,
	}

	engine := NewEngine(opts)
	if engine == nil {
		t.Fatal("Failed to create engine")
	}

	results := engine.Execute([]string{"127.0.0.1"}, []int{22, 80, 443, 8080})

	for _, result := range results {
		if !validStates[result.State] {
			t.Errorf("Invalid scan state %q for port %d", result.State, result.Port)
		}
	}
}
