package ai

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/NycolazSec/tcpcat/internal/scan"
	"github.com/NycolazSec/tcpcat/internal/service"
)

// fakeProber answers from tables keyed by port.
type fakeProber struct {
	ssh  map[int][]string
	http map[string]struct {
		code int
		body string
	}
}

func (f *fakeProber) SSHAuthMethods(host string, port int) ([]string, error) {
	if m, ok := f.ssh[port]; ok {
		return m, nil
	}
	return nil, errors.New("no answer")
}

func (f *fakeProber) HTTPGet(host string, port int, useTLS bool, path string) (int, http.Header, string, error) {
	if r, ok := f.http[strconv.Itoa(port)+path]; ok {
		return r.code, http.Header{}, r.body, nil
	}
	return 0, nil, "", errors.New("no answer")
}

func TestDeepVerifiesHypotheses(t *testing.T) {
	a := analyzer(t)
	ssh22 := open(22, "openssh", "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4")
	ssh2222 := open(2222, "ssh", "SSH-2.0-Gateway")
	ssh2222.SSHPosture = &service.SSHPostureInfo{Warnings: []string{
		"weak key exchange offered: diffie-hellman-group14-sha1", "weak MAC offered: hmac-sha1, hmac-sha1-96"}}
	wings := open(8080, "http", "")
	kubelet := open(10250, "https", "")
	https := open(443, "https", "")
	https.TLS = &service.TLSInfo{Version: "TLS 1.3", PQCReady: true, CertSubject: "TRAEFIK DEFAULT CERT", CertIssuer: "TRAEFIK DEFAULT CERT", Warnings: []string{"self-signed certificate"}}
	closed := scan.TargetResult{IP: "203.0.113.10", Port: 6379, State: "FILTERED"}
	closed2 := scan.TargetResult{IP: "203.0.113.10", Port: 5432, State: "FILTERED"}

	p := &fakeProber{
		ssh: map[int][]string{22: {"publickey"}, 2222: {"password"}},
		http: map[string]struct {
			code int
			body string
		}{
			"8080/api/system": {401, `{"error":"The required authorization heads were not present in the request."}`},
			"10250/pods":      {200, `{"items":[]}`},
		},
	}
	rep := a.Deep([]scan.TargetResult{ssh22, ssh2222, wings, kubelet, https, closed, closed2}, Options{Lang: "en"}, p, nil)

	if f := find(t, rep.Report, 2222); f.Severity != "medium" || !hasCheck(f, CheckIssue, "accepts password logins") || !hasCheck(f, CheckIssue, "weak algorithms") {
		t.Errorf("2222: %+v", f)
	}
	if f := find(t, rep.Report, 2222); !strings.Contains(planText(rep), "x/crypto/ssh") {
		t.Errorf("a non-OpenSSH server gets the Go fix: %+v / %+v", f, rep.Plan)
	}
	if f := find(t, rep.Report, 22); !hasCheck(f, CheckOK, "only accepts key-based logins") {
		t.Errorf("22: %+v", f)
	}
	if f := find(t, rep.Report, 8080); f.Service.ID != "pterodactyl-wings" || f.Verdict != OK || len(f.Service.Alternatives) != 0 {
		t.Errorf("8080 should be confirmed as Wings: %+v", f)
	}
	if f := find(t, rep.Report, 10250); f.Severity != "critical" || f.Verdict != Fix {
		t.Errorf("an anonymous kubelet is critical: %+v", f)
	}
	if f := find(t, rep.Report, 443); !hasCheck(f, CheckNote, "Traefik's default certificate") || hasCheck(f, CheckIssue, "self-signed") {
		t.Errorf("Traefik's default cert by IP is a note, not an issue: %+v", f.Checks)
	}
	prof := strings.Join(rep.Profile, " ")
	for _, want := range []string{"Pterodactyl", "Traefik", "Debian 13"} {
		if !strings.Contains(prof, want) {
			t.Errorf("profile misses %q: %s", want, prof)
		}
	}
	good := strings.Join(rep.Good, "\n")
	if strings.Contains(good, "sensitive ports tested") || !strings.Contains(good, "TLS 1.3") {
		t.Errorf("the kubelet is open, so no \"sensitive ports closed\" good news:\n%s", good)
	}
	if len(rep.Plan) == 0 || rep.Plan[0].Severity != "critical" || !strings.Contains(planText(rep), "SSH entry points") {
		t.Errorf("plan: %+v", rep.Plan)
	}
}

func hasCheck(f Finding, kind, text string) bool {
	for _, c := range f.Checks {
		if c.Kind == kind && strings.Contains(c.Text, text) {
			return true
		}
	}
	return false
}

func planText(rep DeepReport) string {
	var b strings.Builder
	for _, a := range rep.Plan {
		b.WriteString(a.Text + "\n")
	}
	return b.String()
}

// The real probe against a real SSH server: it learns the methods and sends
// no credential.
func TestNetProberSSHAuthMethods(t *testing.T) {
	for name, tc := range map[string]struct {
		password bool
		want     string
	}{"password allowed": {true, "password"}, "keys only": {false, "publickey"}} {
		t.Run(name, func(t *testing.T) {
			addr, gotPassword := startSSHServer(t, tc.password)
			host, portStr, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portStr)
			methods, err := NetProber{Timeout: 3 * time.Second}.SSHAuthMethods(host, port)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(methods, ",") != tc.want {
				t.Fatalf("methods = %v, want %s", methods, tc.want)
			}
			if *gotPassword {
				t.Fatal("the probe sent a password")
			}
		})
	}
}

func startSSHServer(t *testing.T, allowPassword bool) (string, *bool) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	gotPassword := false
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("no")
		},
	}
	if allowPassword {
		cfg.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			gotPassword = true
			return nil, errors.New("no")
		}
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _, _, _ = ssh.NewServerConn(c, cfg)
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().String(), &gotPassword
}

func TestDeepSaysWhenSensitivePortsAreClosed(t *testing.T) {
	a := analyzer(t)
	rs := []scan.TargetResult{
		open(443, "https", ""),
		{IP: "203.0.113.10", Port: 6379, State: "FILTERED"},
		{IP: "203.0.113.10", Port: 5432, State: "CLOSED"},
		{IP: "203.0.113.10", Port: 2375, State: "FILTERED"},
	}
	rep := a.Deep(rs, Options{Lang: "fr"}, &fakeProber{}, nil)
	if !strings.Contains(strings.Join(rep.Good, "\n"), "aucun des 3 ports sensibles testés") {
		t.Errorf("good news: %v", rep.Good)
	}
}

// 2222 is EtherNet/IP's port number, but SSH answered there: the "sensitive
// ports closed" statement must follow what was identified.
func TestGoodNewsFollowsIdentification(t *testing.T) {
	a := analyzer(t)
	rs := []scan.TargetResult{
		open(2222, "ssh", "SSH-2.0-Gateway"),
		{IP: "203.0.113.10", Port: 6379, State: "FILTERED"},
	}
	rep := a.Deep(rs, Options{Lang: "en"}, &fakeProber{}, nil)
	if !strings.Contains(strings.Join(rep.Good, "\n"), "the one sensitive port tested") {
		t.Errorf("good news: %v", rep.Good)
	}
}

func TestInternalAuthCheckSettlesTheFinding(t *testing.T) {
	a := analyzer(t)
	p := &fakeProber{http: map[string]struct {
		code int
		body string
	}{"10250/pods": {401, "Unauthorized"}}}
	rep := a.Deep([]scan.TargetResult{open(10250, "https", "")}, Options{Lang: "en", Vantage: Internal}, p, nil)
	f := rep.Findings[0]
	if f.Verdict != OK || !strings.Contains(f.Title, "refuses anonymous clients") || len(rep.Plan) != 0 {
		t.Fatalf("%+v / plan %+v", f, rep.Plan)
	}
}

func TestWingsSFTPPasswordsAreForPlayers(t *testing.T) {
	a := analyzer(t)
	p := &fakeProber{ssh: map[int][]string{2022: {"password", "publickey"}}}
	rep := a.Deep([]scan.TargetResult{open(2022, "ssh", "SSH-2.0-Go")}, Options{Lang: "en"}, p, nil)
	f := rep.Findings[0]
	if f.Service.ID != "wings-sftp" || f.Severity != "low" || !strings.Contains(planText(rep), "players need them") {
		t.Fatalf("%+v / %+v", f, rep.Plan)
	}
}
