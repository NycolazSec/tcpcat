package remediate

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/NycolazSec/tcpcat/internal/explain"
	"github.com/NycolazSec/tcpcat/internal/inventory"
)

var epoch = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func TestOnlyUnauthorizedExposureIsActionable(t *testing.T) {
	cases := []struct {
		class    string
		expected bool
		want     bool
	}{
		{explain.Exposed, false, true},
		{explain.Forwarded, false, true},
		{explain.Exposed, true, false},   // policy-allowed: nothing to fix
		{explain.Forwarded, true, false}, // ditto
		{explain.Shielded, false, false},
		{explain.Refused, false, false},
		{explain.Local, false, false},
		{explain.Untested, false, false},
	}
	for _, c := range cases {
		e := explain.Entry{Port: 6379, Class: c.class, Expected: c.expected}
		_, ok := For("203.0.113.5", e, nil, epoch)
		if ok != c.want {
			t.Errorf("class %s expected=%v: For ok=%v, want %v", c.class, c.expected, ok, c.want)
		}
	}
}

func TestExposedServiceProducesHostFirewallRule(t *testing.T) {
	e := explain.Entry{
		Port: 6379, Class: explain.Exposed, Service: "redis",
		Owner: &inventory.Owner{PID: 42, Process: "redis-server"},
	}
	b, ok := For("203.0.113.5", e, nil, epoch)
	if !ok {
		t.Fatal("expected a bundle for an unauthorized EXPOSED port")
	}
	if !strings.Contains(b.Summary, "6379") || !strings.Contains(b.Summary, "redis-server") || !strings.Contains(b.Summary, "no policy") {
		t.Errorf("summary = %q", b.Summary)
	}
	// The line applied as-is must be the drop, and it must be scoped off
	// loopback so fixing the exposure can't cut local access.
	if !strings.Contains(b.Nftables, "tcp dport 6379") || !strings.Contains(b.Nftables, "drop") {
		t.Errorf("nftables missing a drop on the port:\n%s", b.Nftables)
	}
	if !strings.Contains(b.Nftables, `iifname != "lo"`) {
		t.Errorf("nftables drop is not scoped off loopback:\n%s", b.Nftables)
	}
	// The permissive allow line must be commented out, never live.
	for _, line := range strings.Split(b.Nftables, "\n") {
		if strings.Contains(line, "accept") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			t.Errorf("an accept line is not commented out: %q", line)
		}
	}
}

func TestIPv6TargetUsesIP6Family(t *testing.T) {
	e := explain.Entry{Port: 443, Class: explain.Exposed}
	b, _ := For("2001:db8::1", e, nil, epoch)
	if !strings.Contains(b.Nftables, "ip6 saddr") {
		t.Errorf("want ip6 family for an IPv6 target:\n%s", b.Nftables)
	}
	e4 := explain.Entry{Port: 443, Class: explain.Exposed}
	b4, _ := For("203.0.113.5", e4, nil, epoch)
	if strings.Contains(b4.Nftables, "ip6 saddr") {
		t.Errorf("want ip (v4) family for an IPv4 target:\n%s", b4.Nftables)
	}
}

func TestSystemdAndKubeOnlyWhenOwnerHasThem(t *testing.T) {
	bare, _ := For("203.0.113.5", explain.Entry{Port: 5432, Class: explain.Exposed}, nil, epoch)
	if bare.Systemd != "" || bare.KubePolicy != "" {
		t.Error("no owner: systemd/kube sections should be empty")
	}

	unit, _ := For("203.0.113.5", explain.Entry{
		Port: 5432, Class: explain.Exposed,
		Owner: &inventory.Owner{Process: "postgres", Unit: "postgresql.service"},
	}, nil, epoch)
	if !strings.Contains(unit.Systemd, "postgresql.service.d/") || !strings.Contains(unit.Systemd, "IPAddressDeny=any") {
		t.Errorf("systemd drop-in wrong:\n%s", unit.Systemd)
	}
	if unit.KubePolicy != "" {
		t.Error("a plain systemd service should get no NetworkPolicy")
	}

	pod, _ := For("203.0.113.5", explain.Entry{
		Port: 8080, Class: explain.Forwarded,
		Owner: &inventory.Owner{Process: "app", Pod: "payments/web-7c9"},
	}, nil, epoch)
	if !strings.Contains(pod.KubePolicy, "namespace: payments") ||
		!strings.Contains(pod.KubePolicy, "ingress: []") ||
		!strings.Contains(pod.KubePolicy, "web-7c9") {
		t.Errorf("network policy wrong:\n%s", pod.KubePolicy)
	}
}

func TestAttestationSignsAndVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	e := explain.Entry{Port: 6379, Class: explain.Exposed, Owner: &inventory.Owner{Process: "redis-server", Unit: "redis.service"}}

	unsigned, _ := For("203.0.113.5", e, nil, epoch)
	if unsigned.Attestation != "" {
		t.Error("a nil key must leave the bundle unsigned")
	}

	b, _ := For("203.0.113.5", e, priv, epoch)
	if b.Attestation == "" || !b.Verify(pub) {
		t.Fatal("signed bundle does not verify with its own public key")
	}
	// Any change to a signed field must break verification.
	tampered := b
	tampered.Nftables += "\nnft add rule inet filter input accept # sneaked in"
	if tampered.Verify(pub) {
		t.Error("verification passed after the firewall rule was altered")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if b.Verify(other) {
		t.Error("verification passed with an unrelated key")
	}
}

func TestFromReportKeepsOnlyExposuresInOrder(t *testing.T) {
	r := explain.Report{
		Target: "203.0.113.5",
		Entries: []explain.Entry{
			{Port: 22, Class: explain.Exposed, Expected: true}, // allowed: skip
			{Port: 6379, Class: explain.Exposed},               // keep
			{Port: 9000, Class: explain.Shielded},              // not reachable: skip
			{Port: 8080, Class: explain.Forwarded},             // keep
		},
	}
	got := FromReport(r, nil, epoch)
	if len(got) != 2 || got[0].Port != 6379 || got[1].Port != 8080 {
		t.Fatalf("FromReport kept %d bundles (%+v), want ports [6379 8080]", len(got), ports(got))
	}
}

func ports(bs []Bundle) []int {
	out := make([]int, len(bs))
	for i, b := range bs {
		out[i] = b.Port
	}
	return out
}
