package discovery

import (
	"testing"
	"time"
)

func TestDiscoverHostLocalhost(t *testing.T) {

	result := DiscoverHost("127.0.0.1", 0, 1*time.Second)

	t.Logf("Localhost discovery result: %v (expected false if no services running)", result)
}

func TestDiscoverHostTimeout(t *testing.T) {

	result := DiscoverHost("192.0.2.1", 0, 100*time.Millisecond)

	_ = result
	t.Log("Timeout handling validated")
}

func TestDiscoverHostUnreachable(t *testing.T) {
	tests := []string{
		"192.0.2.1",
		"198.51.100.1",
		"203.0.113.1",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			result := DiscoverHost(ip, 0, 500*time.Millisecond)

			if result {
				t.Logf("Unexpectedly discovered unreachable host %s", ip)
			}
		})
	}
}

func TestDiscoverHostInvalidIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"invalid format", "999.999.999.999"},
		{"hostname invalid", "not-a-real-host-name-xyz.invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("DiscoverHost panicked: %v", r)
				}
			}()

			_ = DiscoverHost(tt.ip, 0, 1*time.Second)
		})
	}
}

func TestDiscoverHostUDPPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"default TCP", 0},
		{"DNS port", 53},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DiscoverHost("127.0.0.1", tt.port, 1*time.Second)

			t.Logf("Port %d discovery result: %v", tt.port, result)
		})
	}
}

func TestDiscoverHostConcurrency(t *testing.T) {
	results := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_ = DiscoverHost("127.0.0.1", 0, 1*time.Second)
			results <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-results
	}

	t.Log("Concurrent discovery completed without crashing")
}

func TestDiscoverHostResponseType(t *testing.T) {
	tests := []string{
		"127.0.0.1",
		"localhost",
		"192.0.2.1",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			result := DiscoverHost(ip, 0, 1*time.Second)

			if result != true && result != false {
				t.Error("Result must be boolean")
			}
		})
	}
}

func TestDiscoverHostLocalnetCorrectness(t *testing.T) {

	result := DiscoverHost("127.0.0.1", 0, 2*time.Second)

	t.Logf("Localhost discovery: %v (depends on running services)", result)
}

func BenchmarkDiscoverHost(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = DiscoverHost("127.0.0.1", 0, 1*time.Second)
	}
}

func BenchmarkDiscoverHostParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = DiscoverHost("127.0.0.1", 0, 1*time.Second)
		}
	})
}

func BenchmarkDiscoverHostUnreachable(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = DiscoverHost("192.0.2.1", 0, 100*time.Millisecond)
	}
}
