package model

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/NycolazSec/tcpcat/internal/service"
)

// Store must keep a banner exactly as the scanner does, or the model trains
// on text it will never see.
func TestStoreMatchesScanner(t *testing.T) {
	for _, raw := range []string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n",
		"220-first\r\n220 second line of a long multi-line FTP greeting that goes on\r\n",
		"\xff\xfb\x01\xff\xfb\x03login: ",
		"\x4a\x00\x00\x00\x0a10.11.11-MariaDB-0+deb12u1\x00",
		"",
	} {
		if got, want := Store(raw), service.SanitizeBanner(raw); got != want {
			t.Errorf("Store(%q) = %q, scanner stores %q", raw, got, want)
		}
	}
}

func TestConditionsAreDeterministic(t *testing.T) {
	for _, c := range Conditions {
		a, pa := c.Apply("SSH-2.0-OpenSSH_9.6p1 Ubuntu", 22, rand.New(rand.NewSource(7)))
		b, pb := c.Apply("SSH-2.0-OpenSSH_9.6p1 Ubuntu", 22, rand.New(rand.NewSource(7)))
		if a != b || pa != pb {
			t.Errorf("%s is not deterministic for a given seed", c.Name)
		}
	}
}

func TestNormalize(t *testing.T) {
	if got := Normalize("  SSH-2.0-OpenSSH_9.6p1\r\n\x00Ubuntu "); got != "ssh-0.0-openssh_0.0p0 ubuntu" {
		t.Fatalf("Normalize: %q", got)
	}
}

func TestRebrandKeepsTheProtocolNotTheProduct(t *testing.T) {
	got, _ := rebrand("220 mail.example.org ESMTP Postfix (Debian/GNU) ready", 25, rand.New(rand.NewSource(1)))
	if !strings.HasPrefix(got, "220 mail.") || !strings.Contains(got, "ESMTP") || !strings.HasSuffix(got, "ready") {
		t.Fatalf("protocol words lost: %q", got)
	}
	if strings.Contains(got, "Postfix") || strings.Contains(got, "Debian") || len(got) != len("220 mail.example.org ESMTP Postfix (Debian/GNU) ready") {
		t.Fatalf("product kept or shape changed: %q", got)
	}
}

func TestPipelineIsWhatTheScannerWouldStore(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	ssh, _ := pipeline("SSH-2.0-Go", 2022, r)
	if !strings.HasPrefix(ssh, "SSH-2.0-Go\r\n") || !strings.Contains(ssh, "sha2") {
		t.Fatalf("no key exchange after the SSH banner: %q", ssh)
	}
	if got, want := Store(ssh), service.SanitizeBanner(ssh); got != want {
		t.Fatalf("Store(%q) = %q, scanner stores %q", ssh, got, want)
	}
	ftp, _ := pipeline("220 ProFTPD Server", 21, r)
	if !strings.HasPrefix(ftp, "220-") || !strings.HasSuffix(ftp, "\r\n220 ProFTPD Server") {
		t.Fatalf("multi-line greeting: %q", ftp)
	}
	if web, _ := pipeline("nginx", 80, r); web != "nginx" {
		t.Fatalf("a Server header has nothing after it: %q", web)
	}
}
