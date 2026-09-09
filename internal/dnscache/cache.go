package dnscache

import (
	"net"
	"sync"
	"time"
)

type entry struct {
	ips     []string
	expires time.Time
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]entry
	ttl     time.Duration
}

func New(ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]entry),
		ttl:     ttl,
	}
}

func (c *Cache) Lookup(host string) ([]string, error) {

	c.mu.RLock()
	if e, ok := c.entries[host]; ok && time.Now().Before(e.expires) {
		ips := make([]string, len(e.ips))
		copy(ips, e.ips)
		c.mu.RUnlock()
		return ips, nil
	}
	c.mu.RUnlock()

	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}

	var v4 []string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				v4 = append(v4, ip4.String())
			}
		}
	}

	c.mu.Lock()
	c.entries[host] = entry{ips: v4, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()

	return v4, nil
}

func (c *Cache) ResolveParallel(hosts []string) []string {
	type result struct {
		ips []string
	}
	results := make([]result, len(hosts))
	var wg sync.WaitGroup

	for i, h := range hosts {
		wg.Add(1)
		go func(idx int, host string) {
			defer wg.Done()
			ips, _ := c.Lookup(host)
			results[idx] = result{ips: ips}
		}(i, h)
	}
	wg.Wait()

	seen := make(map[string]struct{})
	var out []string
	for _, r := range results {
		for _, ip := range r.ips {
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				out = append(out, ip)
			}
		}
	}
	return out
}
