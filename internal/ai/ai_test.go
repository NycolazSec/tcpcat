package ai

import (
	"strings"
	"testing"

	"github.com/NycolazSec/tcpcat/internal/policy"
	"github.com/NycolazSec/tcpcat/internal/scan"
	"github.com/NycolazSec/tcpcat/internal/vuln"
)

func analyzer(t *testing.T) *Analyzer {
	t.Helper()
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func open(port int, svc, banner string) scan.TargetResult {
	return scan.TargetResult{IP: "203.0.113.10", Port: port, State: "OPEN", Reason: "SYN-ACK Received", Service: svc, Banner: banner}
}

func find(t *testing.T, rep Report, port int) Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Port == port {
			return f
		}
	}
	t.Fatalf("no finding for port %d in %+v", port, rep.Findings)
	return Finding{}
}

func TestJudgesExposureFromTheInternet(t *testing.T) {
	a := analyzer(t)
	rep := a.Analyze([]scan.TargetResult{
		open(443, "https", ""),
		open(22, "openssh", "SSH-2.0-OpenSSH_10.0p2 Debian-7"),
		open(6379, "redis", "-NOAUTH Authentication required."),
		open(25565, "unknown", ""),
		{IP: "203.0.113.10", Port: 3306, State: "CLOSED"},
	}, Options{Lang: "en"})

	if len(rep.Findings) != 4 {
		t.Fatalf("closed ports must be ignored: %d findings", len(rep.Findings))
	}
	if f := rep.Findings[0]; f.Port != 6379 || f.Verdict != Fix || f.Severity != "critical" {
		t.Fatalf("Redis must come first, critical: %+v", f)
	}
	if f := find(t, rep, 22); f.Verdict != Review || f.Service.ID != "openssh" {
		t.Errorf("SSH: %+v", f)
	}
	if f := find(t, rep, 443); f.Verdict != OK {
		t.Errorf("HTTPS: %+v", f)
	}
	if f := find(t, rep, 25565); f.Service.ID != "minecraft" || f.Service.Source != "port" || f.Verdict != OK {
		t.Errorf("Minecraft by port: %+v", f)
	}
	if rep.ToFix != 1 || rep.ToReview != 1 || rep.Fine != 2 {
		t.Errorf("counts: %+v", rep)
	}
	for _, f := range rep.Findings {
		if len(f.Evidence) == 0 || f.Title == "" {
			t.Errorf("port %d: every finding needs a title and evidence", f.Port)
		}
	}
}

// The detector names port 2222 after EtherNet/IP; the banner says SSH.
func TestBannerBeatsPortConvention(t *testing.T) {
	a := analyzer(t)
	rep := a.Analyze([]scan.TargetResult{open(2222, "ethernet-ip", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")}, Options{})
	f := rep.Findings[0]
	if f.Service.ID != "openssh" || f.Service.Source != "model" {
		t.Fatalf("expected OpenSSH from the model, got %+v", f.Service)
	}
	if f.Service.Note != "ethernet-ip" {
		t.Errorf("the disagreement with the detector must be shown: %+v", f.Service)
	}
	if f.Verdict != Review {
		t.Errorf("SSH is restricted, not industrial: %+v", f)
	}
}

func TestSharedPortIsHedged(t *testing.T) {
	a := analyzer(t)
	f := a.Analyze([]scan.TargetResult{open(9000, "unknown", "")}, Options{Lang: "fr"}).Findings[0]
	if f.Service.Source != "port" || len(f.Service.Alternatives) == 0 {
		t.Fatalf("port 9000 is shared: %+v", f.Service)
	}
	if f.Severity != "medium" || !strings.HasSuffix(f.Title, "(à confirmer)") {
		t.Errorf("a port-only guess must be hedged: %+v", f)
	}
}

func TestExploitedVulnerabilityWins(t *testing.T) {
	a := analyzer(t)
	r := open(443, "nginx", "nginx/1.18.0")
	r.Vulnerabilities = []vuln.Vulnerability{
		{ID: "CVE-2021-23017", CVSS: 7.7},
		{ID: "CVE-2099-0001", CVSS: 9.8, KnownExploited: true},
		{ID: "CVE-2099-0002", CVSS: 9.8, Applicability: "Windows only"},
	}
	f := a.Analyze([]scan.TargetResult{r}, Options{}).Findings[0]
	if f.Verdict != Fix || f.Severity != "critical" || !strings.Contains(f.Title, "exploited") {
		t.Fatalf("%+v", f)
	}
	joined := strings.Join(f.Evidence, "\n")
	if !strings.Contains(joined, "known vulnerabilities for this version: 2") || !strings.Contains(joined, "CVE-2099-0001") {
		t.Errorf("evidence: %s", joined)
	}
}

func TestInternalVantage(t *testing.T) {
	a := analyzer(t)
	rep := a.Analyze([]scan.TargetResult{open(5432, "postgresql", ""), open(6379, "redis", ""), open(23, "telnet", "login:")}, Options{Vantage: Internal})
	if f := find(t, rep, 5432); f.Verdict != OK {
		t.Errorf("a database inside the network is expected: %+v", f)
	}
	if f := find(t, rep, 6379); f.Verdict != Review {
		t.Errorf("an unauthenticated-by-default store deserves a check: %+v", f)
	}
	if f := find(t, rep, 23); f.Severity != "medium" {
		t.Errorf("clear-text protocols are flagged anywhere: %+v", f)
	}
}

func TestDraftPolicyIsValid(t *testing.T) {
	a := analyzer(t)
	rep := a.Analyze([]scan.TargetResult{
		open(443, "https", ""), open(22, "openssh", "SSH-2.0-OpenSSH_10.0p2"), open(6379, "redis", ""),
	}, Options{Lang: "fr"})
	y := a.DraftPolicy(rep, "exposition publique")
	p, err := policy.Parse(y)
	if err != nil {
		t.Fatalf("draft does not parse: %v\n%s", err, y)
	}
	r := p.Rules[0]
	if strings.Join(r.Allow, ",") != "22/tcp,443/tcp" || strings.Join(r.Require, ",") != "443" {
		t.Errorf("allow %v require %v", r.Allow, r.Require)
	}
	for _, want := range []string{"6379", "2375", "10250"} {
		if !strings.Contains(","+r.Ports+",", ","+want+",") {
			t.Errorf("the draft must keep checking %s stays closed: %s", want, r.Ports)
		}
	}
	if !strings.Contains(string(y), "à fermer d'abord : 6379 Redis") {
		t.Errorf("draft comments:\n%s", y)
	}
}

// Seen on a real scan from a home connection: the router's FTP helper
// answered port 21 in 7 ms while the server's ports took 80-170 ms.
func TestMiddleboxAnswer(t *testing.T) {
	a := analyzer(t)
	at := func(port int, ms float64, svc string) scan.TargetResult {
		r := open(port, svc, "")
		r.LatencyMs = ms
		return r
	}
	rep := a.Analyze([]scan.TargetResult{at(21, 7.1, "ftp"), at(22, 170, "ssh"), at(80, 80, "http"), at(443, 79, "https"), at(25565, 164, "unknown")}, Options{Lang: "en"})
	f := find(t, rep, 21)
	if f.Severity != "info" || f.Verdict != Review || !strings.Contains(f.Title, "your own network") {
		t.Fatalf("%+v", f)
	}
	if g := find(t, rep, 22); strings.Contains(g.Title, "own network") {
		t.Errorf("normal ports must not be flagged: %+v", g)
	}
}

func TestPortRefinesProtocol(t *testing.T) {
	a := analyzer(t)
	rep := a.Analyze([]scan.TargetResult{open(2022, "ssh", "SSH-2.0-Go"), open(8080, "http", "")}, Options{Lang: "fr"})
	if f := find(t, rep, 2022); f.Service.ID != "wings-sftp" || f.Service.Refined != "ssh" {
		t.Errorf("SSH on 2022: %+v", f.Service)
	}
	f := find(t, rep, 8080)
	if f.Service.ID != "http-alt" || f.Verdict != Review || f.Service.Name != "Service web sur un port alternatif" {
		t.Errorf("HTTP on 8080: %+v", f)
	}
	if len(f.Service.Alternatives) == 0 || f.Service.Alternatives[0] != "Pterodactyl Wings" {
		t.Errorf("8080 could also be Wings: %+v", f.Service.Alternatives)
	}
}

// OpenSSH's advisories often concern the ssh/scp/sftp clients: they do not
// make a scanned server vulnerable.
func TestClientSideFlawsDoNotCount(t *testing.T) {
	a := analyzer(t)
	r := open(22, "openssh", "SSH-2.0-OpenSSH_10.0p2 Debian-7")
	r.Vulnerabilities = []vuln.Vulnerability{
		{ID: "CVE-A", CVSS: 9.4, Title: "ssh in OpenSSH before 10.4 can have a use-after-free when a server changes its host key"},
		{ID: "CVE-B", CVSS: 5.4, Title: "scp in OpenSSH before 10.4 may place a file in the parent directory"},
		{ID: "CVE-C", CVSS: 7.5, Title: "sshd in OpenSSH before 10.4 allows remote attackers to cause a denial of service"},
		{ID: "CVE-D", CVSS: 7.8, Title: "In ssh in OpenSSH before 10.6, a $ or \\ character can occur in a command-line argument"},
		{ID: "CVE-E", CVSS: 6.5, Title: "In sshd and ssh in OpenSSH before 10.6, there is no check for whether the method is allowed"},
	}
	f := a.Analyze([]scan.TargetResult{r}, Options{Lang: "en"}).Findings[0]
	if f.Severity != "medium" || f.Verdict != Review {
		t.Fatalf("only the sshd flaw (7.5) counts: %+v", f)
	}
	ev := strings.Join(f.Evidence, "\n")
	if !strings.Contains(ev, "3 other known flaws concern only the client") || !strings.Contains(ev, "known vulnerabilities for this version: 2") ||
		strings.Contains(ev, "CVE-A") || strings.Contains(ev, "CVE-D") {
		t.Errorf("evidence:\n%s", ev)
	}
}

// A probe that only says "HTTPS" on 10250 found the kubelet's API, not a
// website: the verdict must be the kubelet's.
func TestHTTPIsATransportForAPIs(t *testing.T) {
	a := analyzer(t)
	rep := a.Analyze([]scan.TargetResult{open(10250, "https", ""), open(2375, "http", ""), open(443, "https", "")}, Options{Lang: "en"})
	if f := find(t, rep, 10250); f.Service.ID != "kubelet" || f.Verdict != Fix {
		t.Errorf("10250: %+v", f)
	}
	if f := find(t, rep, 2375); f.Service.ID != "docker-api" || f.Severity != "critical" {
		t.Errorf("2375: %+v", f)
	}
	if f := find(t, rep, 443); f.Service.ID != "https" || f.Verdict != OK {
		t.Errorf("443 stays a website: %+v", f)
	}
}

func TestWebsiteOnAlternatePortIsReviewed(t *testing.T) {
	a := analyzer(t)
	f := a.Analyze([]scan.TargetResult{open(8090, "apache", "Apache/2.4.71 (Debian)")}, Options{Lang: "en"}).Findings[0]
	if f.Service.ID != "apache" || f.Verdict != Review {
		t.Fatalf("%+v", f)
	}
}

// A private service reached from the internet may be open for the scanner's
// own address only: the finding says so before telling to close it.
func TestPrivatePortFromTheInternetMentionsAllowLists(t *testing.T) {
	a := analyzer(t)
	rep := a.Analyze([]scan.TargetResult{open(6443, "kubernetes-api", "HTTP/1.1 401 Unauthorized")}, Options{Lang: "en"})
	f := find(t, rep, 6443)
	if !strings.Contains(strings.Join(f.Evidence, " "), "open for you alone") {
		t.Fatalf("evidence: %v", f.Evidence)
	}
	rep = a.Analyze([]scan.TargetResult{open(6443, "kubernetes-api", "HTTP/1.1 401 Unauthorized")}, Options{Lang: "en", Vantage: Internal})
	if f := find(t, rep, 6443); strings.Contains(strings.Join(f.Evidence, " "), "allow list") {
		t.Fatalf("an internal scan has nothing to say about allow lists: %v", f.Evidence)
	}
}
