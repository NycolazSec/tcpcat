package model

import (
	"math/rand"
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
