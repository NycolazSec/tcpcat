package target

import (
	"reflect"
	"testing"
)

func TestParseTargetSingleIP(t *testing.T) {
	got, err := ParseTarget("192.168.1.1")
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}
	want := []string{"192.168.1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTargetSingleIPv6(t *testing.T) {
	got, err := ParseTarget("2001:db8::1")
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}
	want := []string{"2001:db8::1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTargetIPv6Loopback(t *testing.T) {
	got, err := ParseTarget("::1")
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}
	want := []string{"::1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTargetEmpty(t *testing.T) {
	got, err := ParseTarget("   ")
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestParseTargetCIDR(t *testing.T) {
	got, err := ParseTarget("192.168.1.0/30")
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}
	want := []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTargetInvalidCIDR(t *testing.T) {
	if _, err := ParseTarget("192.168.1.0/99"); err == nil {
		t.Fatal("expected an error for an invalid CIDR")
	}
}

func TestParseTargetOctetRange(t *testing.T) {
	got, err := ParseTarget("10.0.0.1-3")
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTargetFullIPRange(t *testing.T) {
	got, err := ParseTarget("10.0.0.254-10.0.1.1")
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}
	want := []string{"10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTargetInvalidOctetRange(t *testing.T) {
	tests := []string{
		"10.0.0.5-3",   // start > end
		"10.0.0.5-300", // out of byte range
		"10.0.0.1-2-3", // malformed
	}
	for _, target := range tests {
		t.Run(target, func(t *testing.T) {
			if _, err := ParseTarget(target); err == nil {
				t.Errorf("ParseTarget(%q) expected an error, got none", target)
			}
		})
	}
}

func TestParseTargetUnresolvableHostname(t *testing.T) {
	if _, err := ParseTarget("this-host-definitely-does-not-exist.invalid"); err == nil {
		t.Fatal("expected a DNS resolution error")
	}
}

func TestParseTargets(t *testing.T) {
	got, err := ParseTargets([]string{"192.168.1.1", "192.168.1.0/30"})
	if err != nil {
		t.Fatalf("ParseTargets() error = %v", err)
	}
	want := []string{"192.168.1.1", "192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTargetsPropagatesError(t *testing.T) {
	if _, err := ParseTargets([]string{"192.168.1.1", "10.0.0.0/99"}); err == nil {
		t.Fatal("expected an error to propagate from an invalid entry")
	}
}

func TestIncIPCarriesAcrossOctets(t *testing.T) {
	ip := []byte{192, 168, 0, 255}
	incIP(ip)
	want := []byte{192, 168, 1, 0}
	for i := range ip {
		if ip[i] != want[i] {
			t.Fatalf("incIP carried incorrectly: got %v, want %v", ip, want)
		}
	}
}

func TestExpandCIDRSlash32(t *testing.T) {
	got, err := expandCIDR("10.0.0.5/32")
	if err != nil {
		t.Fatalf("expandCIDR() error = %v", err)
	}
	want := []string{"10.0.0.5"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExpandCIDRIPv6Small(t *testing.T) {
	got, err := expandCIDR("2001:db8::/126")
	if err != nil {
		t.Fatalf("expandCIDR() error = %v", err)
	}
	want := []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExpandCIDRIPv6TooLargeIsRejected(t *testing.T) {
	// /64 has 2^64 host addresses -- must be rejected rather than hanging
	// forever trying to enumerate them.
	if _, err := expandCIDR("2001:db8::/64"); err == nil {
		t.Fatal("expected an error for an oversized IPv6 CIDR")
	}
}

func TestExpandCIDRIPv6AtSizeLimitIsAccepted(t *testing.T) {
	// Exactly maxIPv6CIDRHostBits (20) host bits: right at the boundary,
	// should still be accepted (not >, only strictly-greater is rejected).
	got, err := expandCIDR("2001:db8::/108")
	if err != nil {
		t.Fatalf("expandCIDR() error = %v", err)
	}
	if len(got) != 1<<20 {
		t.Fatalf("got %d addresses, want %d", len(got), 1<<20)
	}
}

func TestExpandCIDRNoDuplicates(t *testing.T) {
	got, err := expandCIDR("10.0.0.0/28")
	if err != nil {
		t.Fatalf("expandCIDR() error = %v", err)
	}
	if len(got) != 16 {
		t.Fatalf("got %d addresses, want 16", len(got))
	}
	seen := make(map[string]bool, len(got))
	for _, ip := range got {
		if seen[ip] {
			t.Errorf("duplicate address %s in /28 expansion", ip)
		}
		seen[ip] = true
	}
	if got[0] != "10.0.0.0" || got[len(got)-1] != "10.0.0.15" {
		t.Errorf("expected the range to run 10.0.0.0..10.0.0.15 in order, got first=%s last=%s", got[0], got[len(got)-1])
	}
}
