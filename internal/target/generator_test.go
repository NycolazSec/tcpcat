package target

import (
	"io"
	"net"
	"testing"
)

func TestRandomCIDRGeneratorVisitsEveryAddressExactlyOnce(t *testing.T) {
	gen, err := NewRandomCIDRGenerator("192.168.1.0/28")
	if err != nil {
		t.Fatalf("NewRandomCIDRGenerator() error = %v", err)
	}

	seen := make(map[string]bool)
	for {
		ip, err := gen.NextIP()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextIP() error = %v", err)
		}
		if seen[ip] {
			t.Fatalf("address %s produced twice", ip)
		}
		seen[ip] = true
	}

	if len(seen) != 16 {
		t.Fatalf("visited %d addresses, want 16 (a /28)", len(seen))
	}
	for i := 0; i < 16; i++ {
		want := net.IPv4(192, 168, 1, byte(i)).String()
		if !seen[want] {
			t.Errorf("expected %s to have been visited", want)
		}
	}
}

func TestRandomCIDRGeneratorRejectsIPv6(t *testing.T) {
	if _, err := NewRandomCIDRGenerator("2001:db8::/32"); err == nil {
		t.Fatal("expected an error for an IPv6 CIDR")
	}
}

func TestRandomCIDRGeneratorRejectsInvalidCIDR(t *testing.T) {
	if _, err := NewRandomCIDRGenerator("not-a-cidr"); err == nil {
		t.Fatal("expected an error for an invalid CIDR")
	}
}

func TestGenerateRandomIPsCount(t *testing.T) {
	ips := GenerateRandomIPs(50)
	if len(ips) != 50 {
		t.Fatalf("got %d IPs, want 50", len(ips))
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("generated invalid IP: %q", s)
		}
	}
}

func TestGenerateRandomIPsAvoidsReservedRanges(t *testing.T) {
	ips := GenerateRandomIPs(500)
	for _, s := range ips {
		ip := net.ParseIP(s).To4()
		if ip == nil {
			t.Fatalf("generated invalid IPv4: %q", s)
		}
		o1, o2 := ip[0], ip[1]
		switch {
		case o1 == 0, o1 == 10, o1 == 127:
			t.Errorf("generated reserved address %s (0.0.0.0/8, 10.0.0.0/8, or 127.0.0.0/8)", s)
		case o1 == 169 && o2 == 254:
			t.Errorf("generated link-local address %s", s)
		case o1 == 172 && o2 >= 16 && o2 <= 31:
			t.Errorf("generated private address %s (172.16.0.0/12)", s)
		case o1 == 192 && o2 == 168:
			t.Errorf("generated private address %s (192.168.0.0/16)", s)
		case o1 >= 224:
			t.Errorf("generated multicast/reserved address %s (224.0.0.0/4+)", s)
		}
	}
}

func TestFilterExcludedByIP(t *testing.T) {
	targets := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	got := FilterExcluded(targets, []string{"10.0.0.2"})
	want := []string{"10.0.0.1", "10.0.0.3"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestFilterExcludedByCIDR(t *testing.T) {
	targets := []string{"10.0.0.1", "10.0.1.1", "192.168.1.1"}
	got := FilterExcluded(targets, []string{"10.0.0.0/24"})
	want := []string{"10.0.1.1", "192.168.1.1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestFilterExcludedNoExclusions(t *testing.T) {
	targets := []string{"10.0.0.1", "10.0.0.2"}
	got := FilterExcluded(targets, nil)
	if len(got) != len(targets) {
		t.Fatalf("got %v, want unchanged %v", got, targets)
	}
}

func TestFilterExcludedIgnoresUnparsableTargets(t *testing.T) {
	got := FilterExcluded([]string{"not-an-ip"}, []string{"10.0.0.1"})
	if got != nil {
		t.Errorf("got %v, want nil (unparsable entries are dropped)", got)
	}
}

func TestExpandExclusionsPassesThroughLiterals(t *testing.T) {
	// A CIDR must stay a CIDR: FilterExcluded matches it by containment, so
	// expanding it would pointlessly enumerate the whole prefix.
	resolved, failed := ExpandExclusions([]string{"10.0.0.1", "192.168.0.0/16", " 172.16.0.1 "})
	if len(failed) != 0 {
		t.Errorf("failed = %v, want none for literal entries", failed)
	}
	want := []string{"10.0.0.1", "192.168.0.0/16", "172.16.0.1"}
	if len(resolved) != len(want) {
		t.Fatalf("resolved = %v, want %v", resolved, want)
	}
	for i, w := range want {
		if resolved[i] != w {
			t.Errorf("resolved[%d] = %q, want %q", i, resolved[i], w)
		}
	}
}

func TestExpandExclusionsReportsUnresolvableEntries(t *testing.T) {
	// An exclusion that resolves to nothing protects nothing; it has to be
	// reported rather than silently dropped.
	resolved, failed := ExpandExclusions([]string{"definitely-not-a-real-host.invalid"})
	if len(resolved) != 0 {
		t.Errorf("resolved = %v, want none", resolved)
	}
	if len(failed) != 1 || failed[0] != "definitely-not-a-real-host.invalid" {
		t.Errorf("failed = %v, want the unresolvable entry reported", failed)
	}
}

func TestExpandExclusionsSkipsEmptyEntries(t *testing.T) {
	// "10.0.0.1,,10.0.0.2" splits to an empty middle entry; it is not a
	// failure, just nothing.
	resolved, failed := ExpandExclusions([]string{"10.0.0.1", "", "  "})
	if len(failed) != 0 {
		t.Errorf("failed = %v, want none", failed)
	}
	if len(resolved) != 1 || resolved[0] != "10.0.0.1" {
		t.Errorf("resolved = %v, want just the one real entry", resolved)
	}
}
