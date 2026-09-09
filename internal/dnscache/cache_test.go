package dnscache

import (
	"testing"
	"time"
)

func TestCacheLookupLocalhost(t *testing.T) {
	c := New(5 * time.Minute)
	ips, err := c.Lookup("localhost")
	if err != nil {
		t.Fatalf("Lookup(localhost) error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one IP for localhost")
	}
}

func TestCacheHit(t *testing.T) {
	c := New(5 * time.Minute)

	c.mu.Lock()
	c.entries["testhost"] = entry{
		ips:     []string{"1.2.3.4"},
		expires: time.Now().Add(time.Minute),
	}
	c.mu.Unlock()

	ips, err := c.Lookup("testhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Fatalf("expected [1.2.3.4], got %v", ips)
	}
}

func TestCacheExpiry(t *testing.T) {
	c := New(5 * time.Minute)

	c.mu.Lock()
	c.entries["localhost"] = entry{
		ips:     []string{"255.255.255.255"},
		expires: time.Now().Add(-time.Second),
	}
	c.mu.Unlock()

	ips, err := c.Lookup("localhost")
	if err != nil {
		t.Fatalf("Lookup error after expiry: %v", err)
	}

	for _, ip := range ips {
		if ip == "255.255.255.255" {
			t.Fatal("stale cache entry was returned after expiry")
		}
	}
}

func TestResolveParallelDedup(t *testing.T) {
	c := New(5 * time.Minute)
	c.mu.Lock()
	c.entries["a"] = entry{ips: []string{"1.2.3.4", "1.2.3.5"}, expires: time.Now().Add(time.Minute)}
	c.entries["b"] = entry{ips: []string{"1.2.3.4", "1.2.3.6"}, expires: time.Now().Add(time.Minute)}
	c.mu.Unlock()

	ips := c.ResolveParallel([]string{"a", "b"})
	seen := make(map[string]int)
	for _, ip := range ips {
		seen[ip]++
	}
	for ip, count := range seen {
		if count > 1 {
			t.Errorf("duplicate IP %s returned %d times", ip, count)
		}
	}
	if len(ips) != 3 {
		t.Errorf("expected 3 unique IPs, got %d: %v", len(ips), ips)
	}
}
