package ai

import (
	"strings"
	"testing"

	"github.com/NycolazSec/tcpcat/internal/ai/model"
	"github.com/NycolazSec/tcpcat/internal/scan"
	"github.com/NycolazSec/tcpcat/internal/service"
)

func filtered(port int) scan.TargetResult {
	return scan.TargetResult{IP: "203.0.113.10", Port: port, State: "FILTERED", Reason: "Connection Timeout"}
}

// Every port filtered is no news, not good news: the scanner may be the
// one being blocked.
func TestBlindHostIsNoNews(t *testing.T) {
	a := analyzer(t)
	var rs []scan.TargetResult
	for _, p := range []int{22, 80, 443, 2379, 6443, 10250, 25565} {
		rs = append(rs, filtered(p))
	}
	rep := a.Deep(rs, Options{Lang: "en", Vantage: Internet}, &fakeProber{}, nil)
	if len(rep.Alerts) != 1 || !strings.Contains(rep.Alerts[0], "all 7 ports tested are filtered") {
		t.Fatalf("alerts: %v", rep.Alerts)
	}
	if len(rep.Good) != 0 || len(rep.Profile) != 0 {
		t.Fatalf("nothing answered, yet good news %v / profile %v", rep.Good, rep.Profile)
	}
}

func silentOpen(port int) scan.TargetResult {
	r := open(port, "unknown", "")
	return r
}

// Open ports that all say nothing point at something on the path.
func TestMuteHostAlert(t *testing.T) {
	a := analyzer(t)
	rep := a.Analyze([]scan.TargetResult{silentOpen(22), silentOpen(443), filtered(6443)}, Options{Lang: "en"})
	if len(rep.Alerts) != 1 || !strings.Contains(rep.Alerts[0], "its 2 open ports accept connections") {
		t.Fatalf("alerts: %v", rep.Alerts)
	}
	for _, f := range rep.Findings {
		if !strings.HasSuffix(f.Title, "(to be confirmed)") || !contains(f.Evidence, tr("en", "ev-silent")) {
			t.Errorf("port %d: a silent port is identified by its number only: %+v", f.Port, f)
		}
	}
	// One silent port among talking ones is just that port.
	rep = a.Analyze([]scan.TargetResult{silentOpen(443), open(22, "openssh", "SSH-2.0-OpenSSH_9.6")}, Options{Lang: "en"})
	if len(rep.Alerts) != 0 {
		t.Fatalf("alerts: %v", rep.Alerts)
	}
}

// From a Kubernetes node, an open cluster port may be open for that node
// only: say so instead of sounding the alarm.
func TestClusterNodeVantage(t *testing.T) {
	a := analyzer(t)
	rs := []scan.TargetResult{open(6443, "kubernetes-api", ""), open(22, "openssh", "SSH-2.0-OpenSSH_9.6")}
	plain := find(t, a.Analyze(rs, Options{Lang: "en"}), 6443)
	rep := a.Analyze(rs, Options{Lang: "en", FromClusterNode: true})
	f := find(t, rep, 6443)
	if plain.Verdict != Fix || f.Verdict != Review || f.Severity != "medium" || !strings.HasSuffix(f.Title, "(to be confirmed)") {
		t.Fatalf("from the internet %s/%s, from a node %s/%s %q", plain.Verdict, plain.Severity, f.Verdict, f.Severity, f.Title)
	}
	if len(rep.Alerts) != 1 || !strings.Contains(rep.Alerts[0], "Kubernetes node") {
		t.Fatalf("alerts: %v", rep.Alerts)
	}
	if ssh := find(t, rep, 22); contains(ssh.Evidence, tr("en", "ev-cluster-node")) {
		t.Fatalf("SSH is not a cluster port: %+v", ssh)
	}
}

// A follow-up probe that got no answer is reported, not skipped.
func TestFailedVerificationIsSaid(t *testing.T) {
	a := analyzer(t)
	rep := a.Deep([]scan.TargetResult{silentOpen(22), open(10250, "https", "")}, Options{Lang: "en"}, &fakeProber{}, nil)
	for _, port := range []int{22, 10250} {
		if f := find(t, rep.Report, port); !hasCheck(f, CheckNote, "could not be verified") {
			t.Errorf("port %d: %+v", port, f.Checks)
		}
	}
}

func TestProfileReadsAsASentence(t *testing.T) {
	a := analyzer(t)
	for lang, want := range map[string]string{
		"en": "203.0.113.10: a machine serving websites.",
		"fr": "203.0.113.10 : une machine qui sert des sites web.",
	} {
		rep := a.Deep([]scan.TargetResult{open(443, "https", "")}, Options{Lang: lang}, &fakeProber{}, nil)
		if len(rep.Profile) != 1 || rep.Profile[0] != want {
			t.Errorf("%s: %q, want %q", lang, rep.Profile, want)
		}
	}
}

func TestFamiliesAddUp(t *testing.T) {
	a := analyzer(t)
	fam := a.Families([]model.Guess{{ID: "ftp", P: 0.26}, {ID: "smtp", P: 0.2}, {ID: "proftpd", P: 0.15}, {ID: "vsftpd", P: 0.12}, {ID: "nginx", P: 0.1}})
	if len(fam) < 3 || fam[0].ID != "ftp" || fam[0].P < 0.52 || fam[0].P > 0.54 || fam[1].ID != "smtp" || fam[2].ID != "http" {
		t.Fatalf("families: %+v", fam)
	}
}

// A port silent to service detection that then speaks SSH to the deep
// check was only slow: the check settles what it is.
func TestSlowServiceIsConfirmedByTheCheck(t *testing.T) {
	a := analyzer(t)
	p := &fakeProber{ssh: map[int][]string{22: {"password"}}}
	rep := a.Deep([]scan.TargetResult{silentOpen(22), silentOpen(443), filtered(6443)}, Options{Lang: "en"}, p, nil)
	f := find(t, rep.Report, 22)
	if f.Service.Source != "probe" || strings.HasSuffix(f.Title, "(to be confirmed)") ||
		contains(f.Evidence, tr("en", "ev-silent")) || !contains(f.Evidence, tr("en", "ev-answered-late", "SSH")) {
		t.Fatalf("22 spoke SSH: %+v", f)
	}
	for _, e := range f.Evidence {
		if strings.Contains(e, "identified only by its port") {
			t.Fatalf("still port-only: %v", f.Evidence)
		}
	}
	if len(rep.Alerts) != 0 {
		t.Fatalf("the host answered, it is not mute: %v", rep.Alerts)
	}
	if !hasCheck(find(t, rep.Report, 443), CheckNote, "could not be verified") {
		t.Fatal("443 still never answered")
	}
}

func TestProfileOfOneService(t *testing.T) {
	a := analyzer(t)
	rep := a.Deep([]scan.TargetResult{open(22, "openssh", "SSH-2.0-OpenSSH_9.6")}, Options{Lang: "fr"}, &fakeProber{ssh: map[int][]string{22: {"publickey"}}}, nil)
	if len(rep.Profile) != 1 || !strings.Contains(rep.Profile[0], "une machine qui expose un seul service") {
		t.Fatalf("profile: %q", rep.Profile)
	}
}

// The detector names a silent port by its number (2222 is "ethernet-ip");
// that is still a silent port. An HTTP answer without a Server header is not.
func TestSilentMeansNothingAnswered(t *testing.T) {
	byNumber := open(2222, "ethernet-ip", "")
	if !isSilent(byNumber) {
		t.Fatal("named by its port only, yet not silent")
	}
	web := open(80, "http", "")
	web.HTTPPosture = &service.HTTPPostureInfo{}
	if isSilent(web) {
		t.Fatal("an HTTP server answered")
	}
	if isSilent(open(22, "", "")) {
		t.Fatal("without -sV nothing was asked")
	}
}

// The sshd_config lines of a fix are carried as lines, to copy as they are,
// and the plan points to them instead of repeating them.
func TestWeakSSHFixCarriesConfigLines(t *testing.T) {
	a := analyzer(t)
	r := open(22, "openssh", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
	r.SSHPosture = &service.SSHPostureInfo{Warnings: []string{
		"weak key exchange offered: diffie-hellman-group14-sha1", "weak MAC offered: hmac-sha1, hmac-sha1-96, umac-64@openssh.com, hmac-md5"}}
	rep := a.Deep([]scan.TargetResult{r}, Options{Lang: "en"}, &fakeProber{ssh: map[int][]string{22: {"publickey"}}}, nil)
	var weak Check
	for _, c := range find(t, rep.Report, 22).Checks {
		if strings.Contains(c.Text, "weak algorithms") {
			weak = c
		}
	}
	want := []string{"KexAlgorithms -diffie-hellman-group14-sha1", "MACs -hmac-sha1,hmac-sha1-96,umac-64@openssh.com,hmac-md5"}
	if strings.Join(weak.Lines, "\n") != strings.Join(want, "\n") || !strings.Contains(weak.Text, "(+1 more)") {
		t.Fatalf("check: %+v", weak)
	}
	if p := planText(rep); !strings.Contains(p, "the full fix is in the port's detail below") || strings.Contains(p, "KexAlgorithms") {
		t.Fatalf("plan: %s", p)
	}
}
