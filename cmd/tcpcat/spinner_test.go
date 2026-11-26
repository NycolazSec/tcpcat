package main

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer lets the test read what the spinner's goroutine writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestSpinnerOutsideATerminalOnlyPrintsSteps(t *testing.T) {
	var out syncBuffer
	sp := startSpinnerOn(&out, false, "fr", thinkingVerbs)
	sp.Step("je vérifie 22 (SSH)…")
	time.Sleep(3 * spinnerTick)
	sp.Stop()
	sp.Stop() // twice is fine
	if got := out.String(); strings.Contains(got, "\r") || !strings.Contains(got, "je vérifie 22 (SSH)…") || !strings.HasSuffix(got, "\n") {
		t.Fatalf("a log must not get redraws: %q", got)
	}
}

func TestSpinnerAnimatesOnATerminal(t *testing.T) {
	var out syncBuffer
	sp := startSpinnerOn(&out, true, "fr", verifyingVerbs)
	time.Sleep(spinnerDelay + 4*spinnerTick)
	sp.Step("je vérifie 443 (HTTPS)…")
	time.Sleep(2 * spinnerTick)
	sp.Stop()
	got := out.String()
	if !strings.Contains(got, "Vérification…") || !strings.Contains(got, "je vérifie 443 (HTTPS)…") {
		t.Fatalf("no animation: %q", got)
	}
	frames := 0
	for _, f := range spinnerFrames[:6] {
		if strings.Contains(got, f) {
			frames++
		}
	}
	if frames < 3 {
		t.Fatalf("the star does not turn: %q", got)
	}
	if !strings.HasSuffix(got, "\r\033[K") {
		t.Fatalf("the spinner's line is left on screen: %q", got[max(0, len(got)-40):])
	}
}

func TestSpinnerStaysHiddenForQuickWork(t *testing.T) {
	var out syncBuffer
	sp := startSpinnerOn(&out, true, "en", thinkingVerbs)
	sp.Stop()
	if got := out.String(); got != "" {
		t.Fatalf("instant work must not flicker: %q", got)
	}
}

func TestFrenchNumbers(t *testing.T) {
	if got := number("fr", 92917); got != "92 917" {
		t.Errorf("number: %q", got)
	}
	if got := number("en", 92917); got != "92,917" {
		t.Errorf("number: %q", got)
	}
	if got := decimal("fr", 5.73); got != "5,73" {
		t.Errorf("decimal: %q", got)
	}
	if got := percent("fr", 0.957); got != "95,7 %" {
		t.Errorf("percent: %q", got)
	}
}
