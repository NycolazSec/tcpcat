package explain

import (
	"strings"
	"testing"

	"github.com/NycolazSec/tcpcat/internal/inventory"
	"github.com/NycolazSec/tcpcat/internal/scan"
)

const target = "203.0.113.5"

func sampleInventory() inventory.Inventory {
	return inventory.Inventory{
		Format: inventory.Format, Hostname: "srv",
		Addresses: []string{"127.0.0.1", target, "::1"},
		Listeners: []inventory.Listener{
			{Address: "0.0.0.0", Port: 6379, Owner: &inventory.Owner{PID: 10, Process: "redis-server", Unit: "redis-server.service"}},
			{Address: "0.0.0.0", Port: 5000, Owner: &inventory.Owner{PID: 11, Process: "docker-proxy", ContainerName: "mock-aws", ForwardsTo: "172.17.0.2:5000"}},
			{Address: "::", Port: 5432, Owner: &inventory.Owner{PID: 12, Process: "postgres", Unit: "postgresql@16-main.service"}},
			{Address: "127.0.0.1", Port: 8083, Owner: &inventory.Owner{PID: 13, Process: "docker-proxy", ContainerName: "tcpcat-portal"}},
			{Address: "0.0.0.0", Port: 22, Owner: &inventory.Owner{PID: 14, Process: "sshd", Unit: "ssh.service"}},
			{Address: "0.0.0.0", Port: 9100, Owner: &inventory.Owner{PID: 15, Process: "node_exporter"}},
			{Address: "0.0.0.0", Port: 80, Owner: &inventory.Owner{PID: 16, Process: "nginx"}},
		},
		Services: []inventory.KubeService{{Name: "kube-system/traefik", Type: "LoadBalancer", Port: 443, NodePort: 30443}},
	}
}

func r(port int, state string) scan.TargetResult {
	return scan.TargetResult{IP: target, Port: port, State: state}
}

func sampleScan() []scan.TargetResult {
	return []scan.TargetResult{
		r(6379, scan.StateOpen), r(5000, scan.StateOpen), r(443, scan.StateOpen), r(80, scan.StateOpen),
		r(5432, scan.StateFiltered), r(22, scan.StateClosed), r(8083, scan.StateClosed),
		{IP: "198.51.100.1", Port: 22, State: scan.StateOpen}, // another host: ignored
	}
}

func byPort(rep Report) map[int]Entry {
	m := map[int]Entry{}
	for _, e := range rep.Entries {
		m[e.Port] = e
	}
	return m
}

func TestExplainClassifiesEveryPort(t *testing.T) {
	rep := Explain(sampleInventory(), sampleScan(), target, map[int]bool{80: true})
	got := byPort(rep)

	checks := []struct {
		port              int
		class, sev, inFix string
	}{
		{6379, Exposed, "high", "bind 127.0.0.1"},
		{5000, Exposed, "high", "-p 127.0.0.1:5000:5000"},
		{443, Forwarded, "medium", "kube-system/traefik"},
		{80, Exposed, "info", "--expect"},
		{5432, Shielded, "low", "listen_addresses"},
		{22, Shielded, "low", "ListenAddress"},
		{8083, Local, "info", ""},
		{9100, Untested, "info", "-p 1-65535"},
	}
	for _, c := range checks {
		e, ok := got[c.port]
		if !ok {
			t.Errorf("port %d missing from the report", c.port)
			continue
		}
		if e.Class != c.class || e.Severity != c.sev || !strings.Contains(e.Fix, c.inFix) {
			t.Errorf("port %d: %s/%s fix=%q, want %s/%s containing %q", c.port, e.Class, e.Severity, e.Fix, c.class, c.sev, c.inFix)
		}
	}
	if len(rep.Entries) != len(checks) {
		t.Errorf("%d entries, want %d", len(rep.Entries), len(checks))
	}
	if !strings.Contains(got[6379].Why, "redis-server (pid 10, unit redis-server.service)") {
		t.Errorf("redis why = %q", got[6379].Why)
	}
	if !strings.Contains(got[5000].Why, "container mock-aws") {
		t.Errorf("docker why = %q", got[5000].Why)
	}
	if got[443].Kube == nil || got[443].Kube.Name != "kube-system/traefik" {
		t.Errorf("443 should be attributed to the traefik Service: %+v", got[443])
	}

	// Unexpected exposures first, then by class; the expected port 80 last.
	if rep.Entries[0].Class != Exposed || rep.Entries[len(rep.Entries)-1].Port != 80 {
		t.Errorf("order: first %+v, last %+v", rep.Entries[0], rep.Entries[len(rep.Entries)-1])
	}
	if rep.Problems() != 3 { // 6379, 5000, 443 -- not the expected 80
		t.Errorf("Problems() = %d, want 3", rep.Problems())
	}
}

func TestForwardedWhenOnlyLoopbackListens(t *testing.T) {
	inv := sampleInventory()
	rep := Explain(inv, []scan.TargetResult{r(8083, scan.StateOpen)}, target, nil)
	e := byPort(rep)[8083]
	if e.Class != Forwarded || !strings.Contains(e.Why, "127.0.0.1 only") {
		t.Errorf("8083 = %+v", e)
	}
}

func TestSelectTarget(t *testing.T) {
	inv := sampleInventory()
	if got, err := SelectTarget(inv, sampleScan(), ""); err != nil || got != target {
		t.Errorf("SelectTarget auto = %q, %v", got, err)
	}
	if _, err := SelectTarget(inv, sampleScan(), "192.0.2.99"); err == nil {
		t.Error("an address absent from the scan must be refused")
	}
	natScan := []scan.TargetResult{{IP: "198.51.100.7", Port: 22, State: scan.StateOpen}}
	_, err := SelectTarget(inv, natScan, "")
	if err == nil || !strings.Contains(err.Error(), "--target 198.51.100.7") {
		t.Errorf("NAT case should suggest --target, got %v", err)
	}
	if got, err := SelectTarget(inv, natScan, "198.51.100.7"); err != nil || got != "198.51.100.7" {
		t.Errorf("explicit target = %q, %v", got, err)
	}
}

func TestCovers(t *testing.T) {
	cases := []struct {
		bound, target string
		want          bool
	}{
		{"0.0.0.0", "203.0.113.5", true},
		{"0.0.0.0", "2001:db8::1", false},
		{"::", "203.0.113.5", true},
		{"::", "2001:db8::1", true},
		{"127.0.0.1", "203.0.113.5", false},
		{"203.0.113.5", "203.0.113.5", true},
	}
	for _, c := range cases {
		if got := covers(c.bound, c.target); got != c.want {
			t.Errorf("covers(%s, %s) = %v", c.bound, c.target, got)
		}
	}
}

// On a k3s node, nginx can listen on 0.0.0.0:80 while the service load
// balancer redirects external :80 to Traefik: the Service wins.
func TestKubeServiceTakesPrecedenceOverLocalListener(t *testing.T) {
	inv := sampleInventory()
	inv.Services = append(inv.Services, inventory.KubeService{Name: "kube-system/traefik", Type: "LoadBalancer", Port: 80, NodePort: 30080})
	e := byPort(Explain(inv, []scan.TargetResult{r(80, scan.StateOpen)}, target, nil))[80]
	if e.Class != Forwarded || e.Kube == nil || !strings.Contains(e.Why, "nginx (pid 16) also listens") {
		t.Errorf("80 = %+v", e)
	}
}
