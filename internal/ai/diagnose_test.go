package ai

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NycolazSec/tcpcat/internal/scan"
)

// fakeNet answers the diagnosis from a script: per port, the states Dial
// returns call after call (the last one repeats), and what FirstBytes hears.
type fakeNet struct {
	fakeProber
	mu     sync.Mutex
	states map[int][]string
	calls  map[int]int
	banner map[int]struct {
		delay time.Duration
		data  string
	}
}

func (f *fakeNet) Dial(host string, port int, timeout time.Duration) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.states[port]
	if len(s) == 0 {
		return "filtered"
	}
	i := min(f.calls[port], len(s)-1)
	f.calls[port]++
	return s[i]
}

func (f *fakeNet) FirstBytes(host string, port int, wait time.Duration) (bool, time.Duration, string) {
	b, ok := f.banner[port]
	if !ok {
		return true, wait, ""
	}
	return true, b.delay, b.data
}

func newFakeNet() *fakeNet {
	return &fakeNet{states: map[int][]string{}, calls: map[int]int{}, banner: map[int]struct {
		delay time.Duration
		data  string
	}{}}
}

func fastDiagnosis(t *testing.T) {
	t.Helper()
	d, c, b, g := diagDialTimeout, diagCoolDown, diagBannerWait, diagSlowGap
	diagDialTimeout, diagCoolDown, diagBannerWait, diagSlowGap = time.Millisecond, time.Millisecond, time.Millisecond, 0
	t.Cleanup(func() { diagDialTimeout, diagCoolDown, diagBannerWait, diagSlowGap = d, c, b, g })
}

func joined(rep DeepReport) string {
	return strings.Join(append(append([]string{}, rep.Story...), rep.Alerts...), "\n")
}

func TestStoryReadsTheFiltering(t *testing.T) {
	closed := func(p int) scan.TargetResult {
		return scan.TargetResult{IP: "203.0.113.10", Port: p, State: "CLOSED", Reason: "RST Received"}
	}
	rejected := func(p int) scan.TargetResult {
		return scan.TargetResult{IP: "203.0.113.10", Port: p, State: "FILTERED", Reason: "ICMP Port Unreachable"}
	}
	for name, tc := range map[string]struct {
		rs   []scan.TargetResult
		want string
	}{
		"whitelist":   {[]scan.TargetResult{open(22, "ssh", ""), filtered(23), filtered(25)}, "drops everything else silently"},
		"no firewall": {[]scan.TargetResult{open(22, "ssh", ""), closed(23), closed(25)}, "nothing filters them, or a firewall refuses them with a reset"},
		"partial":     {[]scan.TargetResult{open(22, "ssh", ""), closed(8443), filtered(25), filtered(26)}, "(closed: 8443)"},
		"reject":      {[]scan.TargetResult{open(22, "ssh", ""), rejected(3306), filtered(25)}, "refuses some ports out loud (3306)"},
	} {
		story := strings.Join(scanStory(tc.rs, "en"), "\n")
		if !strings.Contains(story, tc.want) {
			t.Errorf("%s: %s", name, story)
		}
	}
	slow := []scan.TargetResult{open(22, "ssh", ""), filtered(23), filtered(25)}
	slow[0].LatencyMs = 850
	slow[1].LatencyMs, slow[2].LatencyMs = 1000, 1000
	if story := strings.Join(scanStory(slow, "fr"), "\n"); !strings.Contains(story, "jusqu'à 850 ms") || !strings.Contains(story, "délai de 1000 ms") {
		t.Errorf("slow: %s", story)
	}
}

// Open during the scan, filtered right after, back after a pause: the pace
// of the scan set off a temporary limit.
func TestDiagnosisSeesATemporaryLimit(t *testing.T) {
	fastDiagnosis(t)
	a := analyzer(t)
	n := newFakeNet()
	n.states[22] = []string{"filtered", "open"}
	n.ssh = map[int][]string{22: {"publickey"}}
	rep := a.Deep([]scan.TargetResult{open(22, "openssh", "SSH-2.0-OpenSSH_9.6"), filtered(23), filtered(25)}, Options{Lang: "en"}, n, nil)
	text := joined(rep)
	if !strings.Contains(text, "ports 22 answered during the scan and no longer do") || !strings.Contains(text, "port 22 answers again: a temporary limit") {
		t.Fatal(text)
	}
}

func TestDiagnosisSeesABan(t *testing.T) {
	fastDiagnosis(t)
	a := analyzer(t)
	n := newFakeNet()
	n.states[22] = []string{"filtered"}
	rep := a.Deep([]scan.TargetResult{open(22, "openssh", "SSH-2.0-OpenSSH_9.6"), filtered(23), filtered(25)}, Options{Lang: "fr"}, n, nil)
	if text := joined(rep); !strings.Contains(text, "c'est un bannissement") {
		t.Fatal(text)
	}
}

func TestDiagnosisOfANormalScan(t *testing.T) {
	fastDiagnosis(t)
	a := analyzer(t)
	n := newFakeNet()
	n.states[22] = []string{"open"}
	rep := a.Deep([]scan.TargetResult{open(22, "openssh", "SSH-2.0-OpenSSH_9.6"), filtered(23), filtered(25)}, Options{Lang: "en"}, n, nil)
	if text := joined(rep); !strings.Contains(text, "nothing blocked your address") || len(rep.Alerts) != 0 {
		t.Fatal(text)
	}
}

// Everything filtered: one slow connection gets through, so the pace was
// blocked, not the address.
func TestDiagnosisOfABlindHost(t *testing.T) {
	fastDiagnosis(t)
	a := analyzer(t)
	rs := []scan.TargetResult{filtered(22), filtered(80), filtered(443), filtered(6443)}
	n := newFakeNet()
	n.states[80] = []string{"open"}
	if text := joined(a.Deep(rs, Options{Lang: "en"}, n, nil)); !strings.Contains(text, "answers a single slow connection on port 80") {
		t.Fatal(text)
	}
	n = newFakeNet()
	if text := joined(a.Deep(rs, Options{Lang: "en"}, n, nil)); !strings.Contains(text, "nothing answers, not even one slow connection") {
		t.Fatal(text)
	}
}

// A service silent to detection that speaks after two seconds: its banner
// joins the analysis, which then names it.
func TestDiagnosisHearsASlowBanner(t *testing.T) {
	fastDiagnosis(t)
	a := analyzer(t)
	n := newFakeNet()
	n.states[22] = []string{"open"}
	n.banner[22] = struct {
		delay time.Duration
		data  string
	}{2800 * time.Millisecond, "SSH-2.0-OpenSSH_9.6p1 Debian-5\r\n"}
	n.ssh = map[int][]string{22: {"password"}}
	rep := a.Deep([]scan.TargetResult{silentOpen(22), filtered(23), filtered(25)}, Options{Lang: "fr"}, n, nil)
	if text := joined(rep); !strings.Contains(text, "bannière au bout de 2,8 s") || !strings.Contains(text, "UseDNS") {
		t.Fatal(text)
	}
	f := find(t, rep.Report, 22)
	if f.Service.ID != "openssh" || strings.HasSuffix(f.Title, "(à confirmer)") {
		t.Fatalf("the late banner names it: %+v", f)
	}
	// A server that should speak first and never does is reported too.
	n.banner = nil
	rep = a.Deep([]scan.TargetResult{silentOpen(22), filtered(23), filtered(25)}, Options{Lang: "en"}, n, nil)
	if text := joined(rep); !strings.Contains(text, "no banner even after") {
		t.Fatal(text)
	}
}

// When the host blocked the scanner, a service that answers the follow-up
// check was cut off by the block, not slow.
func TestLateAnswerAfterABlockIsExplainedByTheBlock(t *testing.T) {
	fastDiagnosis(t)
	a := analyzer(t)
	n := newFakeNet()
	n.states[80] = []string{"filtered", "open"}
	n.http = map[string]struct {
		code int
		body string
	}{"80/": {200, "<html></html>"}}
	rep := a.Deep([]scan.TargetResult{silentOpen(80), filtered(23), filtered(25)}, Options{Lang: "en"}, n, nil)
	f := find(t, rep.Report, 80)
	if !contains(f.Evidence, tr("en", "ev-answered-after-block", "HTTP")) || contains(f.Evidence, tr("en", "ev-answered-late", "HTTP")) {
		t.Fatalf("evidence: %v", f.Evidence)
	}
}

// Port 25 answering closed among filtered ports is most often the scanner's
// internet provider blocking outgoing mail, not an opening rule left behind.
func TestStoryTellsAnSMTPBlockFromALeftoverRule(t *testing.T) {
	closed := func(p int) scan.TargetResult {
		return scan.TargetResult{IP: "203.0.113.10", Port: p, State: "CLOSED", Reason: "RST Received"}
	}
	story := strings.Join(scanStory([]scan.TargetResult{open(22, "ssh", ""), closed(25), closed(25566), filtered(23), filtered(24)}, "en"), "\n")
	if !strings.Contains(story, "internet providers block outgoing mail") || !strings.Contains(story, "(closed: 25566)") || strings.Contains(story, "closed: 25,") {
		t.Fatal(story)
	}
	if !strings.Contains(story, "or services that are stopped") {
		t.Fatal(story)
	}
	story = strings.Join(scanStory([]scan.TargetResult{open(22, "ssh", ""), closed(25), filtered(23)}, "en"), "\n")
	if strings.Contains(story, "opening rules") {
		t.Fatalf("port 25 alone is no leftover rule: %s", story)
	}
}

// Behind a home router, a block may be the router's own: the diagnosis says
// so, and points to fewer connections at once.
func TestDiagnosisBehindARouterSuspectsTheRouterToo(t *testing.T) {
	fastDiagnosis(t)
	a := analyzer(t)
	n := newFakeNet()
	n.states[22] = []string{"filtered", "open"}
	n.ssh = map[int][]string{22: {"publickey"}}
	rs := []scan.TargetResult{open(22, "openssh", "SSH-2.0-OpenSSH_9.6"), filtered(23), filtered(25)}
	text := joined(a.Deep(rs, Options{Lang: "en", BehindNAT: true}, n, nil))
	if !strings.Contains(text, "your own router ran out of room") || !strings.Contains(text, "-w 16 --rate 50") {
		t.Fatal(text)
	}
	n = newFakeNet()
	n.states[22] = []string{"filtered"}
	if text := joined(a.Deep(rs, Options{Lang: "fr", BehindNAT: true}, n, nil)); !strings.Contains(text, "c'est un bannissement") || !strings.Contains(text, "derrière une box") {
		t.Fatal(text)
	}
	// Without a router, the machine's protection stays the only suspect.
	n = newFakeNet()
	n.states[22] = []string{"filtered", "open"}
	n.ssh = map[int][]string{22: {"publickey"}}
	if text := joined(a.Deep(rs, Options{Lang: "en"}, n, nil)); strings.Contains(text, "router") {
		t.Fatal(text)
	}
}

func TestBlindHostBehindARouter(t *testing.T) {
	fastDiagnosis(t)
	a := analyzer(t)
	rs := []scan.TargetResult{filtered(22), filtered(80), filtered(443), filtered(6443)}
	rep := a.Analyze(rs, Options{Lang: "en", BehindNAT: true})
	if len(rep.Alerts) == 0 || !strings.Contains(rep.Alerts[0], "fill its connection table") {
		t.Fatal(rep.Alerts)
	}
	n := newFakeNet()
	n.states[80] = []string{"open"}
	if text := joined(a.Deep(rs, Options{Lang: "en", BehindNAT: true}, n, nil)); !strings.Contains(text, "answers a single slow connection on port 80") || !strings.Contains(text, "your own router") {
		t.Fatal(text)
	}
}
