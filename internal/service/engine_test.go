package service

import (
	"testing"
	"time"
)

func TestDetectServiceLocalhost(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port int
	}{
		{"SSH", "127.0.0.1", 22},
		{"HTTP", "127.0.0.1", 80},
		{"HTTPS", "127.0.0.1", 443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectService(tt.ip, tt.port, 2*time.Second, false)

			if result.Name == "" {
				t.Logf("Service detection returned empty name for %s:%d", tt.ip, tt.port)
			}
		})
	}
}

func TestDetectServiceTimeout(t *testing.T) {

	result := DetectService("192.0.2.1", 12345, 1*time.Millisecond, false)

	if result.Name == "" {
		t.Log("Timeout returned empty service name (expected)")
	}
}

func TestDetectServiceResponseStructure(t *testing.T) {
	result := DetectService("127.0.0.1", 22, 2*time.Second, false)

	if result.Name == "" {
		t.Error("Result has empty Name")
	}

	if len(result.Version) > 100 {
		t.Errorf("Version unreasonably long: %d chars", len(result.Version))
	}

	if len(result.Banner) > 1000 {
		t.Errorf("Banner unreasonably long: %d chars", len(result.Banner))
	}

	if len(result.OS) > 50 {
		t.Errorf("OS unreasonably long: %d chars", len(result.OS))
	}
}

func TestDetectServiceCommonPorts(t *testing.T) {
	commonPorts := []int{22, 80, 443, 3306, 5432, 6379}

	for _, port := range commonPorts {
		t.Run(string(rune(port)), func(t *testing.T) {
			result := DetectService("127.0.0.1", port, 2*time.Second, false)

			if len(result.Name) > 50 {
				t.Errorf("Service name unreasonably long: %s", result.Name)
			}
		})
	}
}

func TestDetectServiceConcurrency(t *testing.T) {
	results := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(port int) {
			result := DetectService("127.0.0.1", port, 1*time.Second, false)
			results <- result.Name != ""
		}(22 + i)
	}

	for i := 0; i < 10; i++ {
		<-results
	}
}

func TestDetectServiceInsecureSkipVerify(t *testing.T) {

	tests := []struct {
		name     string
		insecure bool
	}{
		{"secure", false},
		{"insecure", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectService("127.0.0.1", 443, 1*time.Second, tt.insecure)
			if result.Name == "" {
				t.Log("Expected behavior with insecure flag")
			}
		})
	}
}

func BenchmarkDetectService(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = DetectService("127.0.0.1", 22, 1*time.Second, false)
	}
}

func BenchmarkDetectServiceParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		port := 22
		for pb.Next() {
			_ = DetectService("127.0.0.1", port, 1*time.Second, false)
			port++
			if port > 443 {
				port = 22
			}
		}
	})
}
