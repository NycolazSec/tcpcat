package evidence

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NycolazSec/tcpcat/internal/scan"
	"github.com/NycolazSec/tcpcat/internal/vuln"
)

func sampleResults() []scan.TargetResult {
	return []scan.TargetResult{
		{IP: "127.0.0.1", Port: 22, State: scan.StateOpen, Service: "ssh", Version: "OpenSSH_9.6", Banner: "SSH-2.0-OpenSSH_9.6",
			Vulnerabilities: []vuln.Vulnerability{{ID: "CVE-2024-6387"}}, RiskSeverity: "high"},
		{IP: "127.0.0.1", Port: 23, State: scan.StateClosed},
		{IP: "127.0.0.1", Port: 8080, State: scan.StateOpen},
	}
}

func TestBuildKeepsOnlyOpenPortsWithStableIDs(t *testing.T) {
	b := Build(sampleResults(), Tool{Name: "tcpcat", Version: "test"}, []string{"127.0.0.1", "-sV"}, time.Unix(0, 0))
	if b.Format != Format || len(b.Findings) != 2 {
		t.Fatalf("bundle = %+v", b)
	}
	ssh := b.Findings[0]
	if ssh.Port != 22 || ssh.ID != FindingID("127.0.0.1", 22) || ssh.BannerSHA256 != BannerHash("SSH-2.0-OpenSSH_9.6") {
		t.Errorf("ssh finding = %+v", ssh)
	}
	if len(ssh.Vulnerabilities) != 1 || ssh.SourceIP == "" {
		t.Errorf("ssh finding should carry its CVE and a source IP: %+v", ssh)
	}
	if FindingID("127.0.0.1", 22) == FindingID("127.0.0.1", 2222) {
		t.Error("finding IDs collide")
	}
}

func TestRedactArgs(t *testing.T) {
	got := RedactArgs([]string{"10.0.0.1", "--vulners-apikey", "abc", "--notify-webhook=https://hooks/x", "-p", "22", "--evidence-key", "k.key"})
	want := "10.0.0.1 --vulners-apikey REDACTED --notify-webhook=REDACTED -p 22 --evidence-key REDACTED"
	if strings.Join(got, " ") != want {
		t.Errorf("RedactArgs = %q", strings.Join(got, " "))
	}
}

func TestSignVerifyAndTamper(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "auditor")
	pubPath, keyPath, err := GenerateKeyPair(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := GenerateKeyPair(prefix); err == nil {
		t.Error("GenerateKeyPair must refuse to overwrite an existing key")
	}
	if info, _ := os.Stat(keyPath); info.Mode().Perm() != 0600 {
		t.Errorf("private key mode = %v", info.Mode().Perm())
	}
	signer, err := LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}

	bundlePath := filepath.Join(dir, "evidence.json")
	if err := Write(bundlePath, Build(sampleResults(), Tool{Name: "tcpcat"}, nil, time.Now()), signer); err != nil {
		t.Fatal(err)
	}
	_, data, err := Load(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(bundlePath + ".sig")
	digest, _ := os.ReadFile(bundlePath + ".sha256")
	if err := Verify(pub, data, string(sig)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := VerifyDigest(data, string(digest)); err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}

	tampered := []byte(strings.Replace(string(data), `"port": 22`, `"port": 2222`, 1))
	if err := Verify(pub, tampered, string(sig)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered bundle: Verify = %v, want ErrBadSignature", err)
	}
	if err := VerifyDigest(tampered, string(digest)); err == nil {
		t.Error("tampered bundle passed the digest check")
	}
	if Fingerprint(pub) == "" {
		t.Error("empty fingerprint")
	}
}

func TestReplay(t *testing.T) {
	findings := []Finding{
		{IP: "h", Port: 22, BannerSHA256: BannerHash("SSH-2.0-OpenSSH_9.6"), Banner: "SSH-2.0-OpenSSH_9.6"},
		{IP: "h", Port: 21, BannerSHA256: BannerHash("220 vsFTPd 2.3.4")},
		{IP: "h", Port: 3306},
		{IP: "h", Port: 80, BannerSHA256: BannerHash("x")},
		{IP: "h", Port: 9999},
	}
	probe := func(_ string, port int) (bool, string, error) {
		switch port {
		case 22:
			return true, "SSH-2.0-OpenSSH_9.6\r\n", nil
		case 21:
			return true, "220 ProFTPD\r\n", nil
		case 3306:
			return false, "", nil
		case 80:
			return true, "", nil // silent service: banner can't be compared
		}
		return false, "", errors.New("boom")
	}
	got := Replay(findings, probe)
	want := []string{OutcomeReproduced, OutcomeChanged, OutcomeFixed, OutcomeReproduced, OutcomeReproduced}
	for i, o := range got {
		if o.Result != want[i] {
			t.Errorf("finding %d (port %d): %s, want %s (%s)", i, o.Finding.Port, o.Result, want[i], o.Detail)
		}
	}
}
