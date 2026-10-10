package dualstack

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/NycolazSec/tcpcat/internal/scan"
)

type fakeResolver struct {
	aaaa map[string][]string
	ptr  map[string][]string
}

func (f fakeResolver) LookupIP(_ context.Context, network, host string) ([]net.IP, error) {
	if network != "ip6" {
		return nil, errors.New("unexpected network " + network)
	}
	var out []net.IP
	for _, s := range f.aaaa[host] {
		out = append(out, net.ParseIP(s))
	}
	if len(out) == 0 {
		return nil, errors.New("no such host")
	}
	return out, nil
}

func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if names, ok := f.ptr[addr]; ok {
		return names, nil
	}
	return nil, errors.New("no PTR")
}

func TestFindPairs(t *testing.T) {
	r := fakeResolver{
		aaaa: map[string][]string{
			"www.example.com": {"2001:db8::10", "2001:db8::10"}, // duplicate collapses
			"db.example.com":  {"2001:db8::20"},
			"v4only.example":  {},
		},
		ptr: map[string][]string{"192.0.2.20": {"db.example.com."}},
	}
	names := map[string]string{"192.0.2.10": "www.example.com", "192.0.2.30": "v4only.example"}
	pairs := FindPairs(context.Background(), []string{"192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.40", "2001:db8::99"}, names, r)

	if len(pairs) != 2 {
		t.Fatalf("pairs = %+v", pairs)
	}
	if pairs[0] != (Pair{Name: "www.example.com", IPv4: "192.0.2.10", IPv6: "2001:db8::10"}) {
		t.Errorf("pair 0 = %+v", pairs[0])
	}
	if pairs[1] != (Pair{Name: "db.example.com", IPv4: "192.0.2.20", IPv6: "2001:db8::20"}) {
		t.Errorf("pair 1 (via PTR, trailing dot trimmed) = %+v", pairs[1])
	}
	if got := strings.Join(IPv6Targets(append(pairs, pairs[0])), ","); got != "2001:db8::10,2001:db8::20" {
		t.Errorf("IPv6Targets = %s", got)
	}
}

func open(ip string, port int) scan.TargetResult {
	return scan.TargetResult{IP: ip, Port: port, State: scan.StateOpen}
}

func TestCompareAndAnnotate(t *testing.T) {
	pairs := []Pair{{Name: "www.example.com", IPv4: "192.0.2.10", IPv6: "2001:db8::10"}}
	v4 := []scan.TargetResult{open("192.0.2.10", 443), open("192.0.2.10", 80), {IP: "192.0.2.10", Port: 22, State: scan.StateFiltered}}
	v6 := []scan.TargetResult{open("2001:db8::10", 443), open("2001:db8::10", 22), open("2001:db8::10", 8080)}

	gaps := Compare(pairs, v4, v6)
	if len(gaps) != 3 {
		t.Fatalf("gaps = %+v", gaps)
	}
	if gaps[0].Kind != GapIPv6Only || gaps[0].Port != 22 || !gaps[0].Sensitive {
		t.Errorf("gap 0 = %+v (want SSH ipv6-only, sensitive)", gaps[0])
	}
	if gaps[1].Kind != GapIPv6Only || gaps[1].Port != 8080 || gaps[1].Sensitive {
		t.Errorf("gap 1 = %+v", gaps[1])
	}
	if gaps[2].Kind != GapIPv4Only || gaps[2].Port != 80 {
		t.Errorf("gap 2 = %+v", gaps[2])
	}

	v6[1].RiskSeverity = "low"
	if n := Annotate(v6, gaps); n != 2 {
		t.Fatalf("Annotate touched %d results, want 2", n)
	}
	ssh := v6[1]
	if ssh.DualStack == nil || ssh.DualStack.Counterpart != "192.0.2.10" || ssh.RiskSeverity != "high" {
		t.Errorf("SSH result = %+v", ssh)
	}
	if len(ssh.Findings) != 1 || !strings.Contains(ssh.Findings[0], "IPv6-only exposure: port 22") {
		t.Errorf("SSH findings = %v", ssh.Findings)
	}
	if v6[2].RiskSeverity != "medium" {
		t.Errorf("non-sensitive gap severity = %q", v6[2].RiskSeverity)
	}
	if v6[0].DualStack != nil {
		t.Errorf("443 is open on both families and must not be annotated")
	}
}
