package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/NycolazSec/tcpcat/config"
)

// spinner shows that the AI is working: a twinkling star, what it is doing,
// and for how long, on one line it redraws in place. The steps it is told
// about are printed above that line, so they stay in the scrollback.
//
// It only animates on a terminal. Anywhere else (a pipe, a file, a CI log)
// it prints each step once and nothing else, so the output stays readable.
// It never delays the work: a short task finishes before it first draws.
type spinner struct {
	mu      sync.Mutex
	out     io.Writer
	lang    string
	verbs   [][2]string
	created time.Time
	frame   int
	drawn   bool
	tty     bool
	stop    chan struct{}
	done    chan struct{}
}

var spinnerFrames = []string{"·", "✢", "✳", "✶", "✻", "✽", "✻", "✶", "✳", "✢"}

const (
	spinnerColor = "\033[38;5;209m" // a warm orange, like Claude's
	spinnerTick  = 120 * time.Millisecond
	// spinnerDelay is how long work must last before the spinner shows:
	// nothing flickers for an analysis that takes a few milliseconds.
	spinnerDelay = 150 * time.Millisecond
	// verbEvery is how often the verb changes.
	verbEvery = 3 * time.Second
)

// thinkingVerbs are what the AI is doing while it reads a scan.
var thinkingVerbs = [][2]string{
	{"Thinking", "Réflexion"},
	{"Reading the evidence", "Lecture des preuves"},
	{"Cross-checking", "Recoupement"},
	{"Weighing the risks", "Pesée des risques"},
}

// verifyingVerbs are what it does while its follow-up probes run.
var verifyingVerbs = [][2]string{
	{"Verifying", "Vérification"},
	{"Waiting for answers", "Attente des réponses"},
	{"Cross-checking", "Recoupement"},
	{"Testing the hypotheses", "Test des hypothèses"},
	{"Drawing up the plan", "Préparation du plan"},
}

func startSpinner(lang string, verbs [][2]string) *spinner {
	return startSpinnerOn(os.Stdout, isTerminal(os.Stdout), lang, verbs)
}

func startSpinnerOn(out io.Writer, tty bool, lang string, verbs [][2]string) *spinner {
	s := &spinner{
		out: out, lang: lang, verbs: verbs, created: time.Now(),
		tty: tty, stop: make(chan struct{}), done: make(chan struct{}),
	}
	if !s.tty {
		close(s.done)
		return s
	}
	go s.run()
	return s
}

func (s *spinner) run() {
	defer close(s.done)
	t := time.NewTicker(spinnerTick)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			s.mu.Lock()
			s.clear()
			s.mu.Unlock()
			return
		case <-t.C:
			s.mu.Lock()
			s.frame++
			if time.Since(s.created) >= spinnerDelay {
				s.draw()
			}
			s.mu.Unlock()
		}
	}
}

// Step prints what has just started, above the spinner's line.
func (s *spinner) Step(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clear()
	_, _ = fmt.Fprintf(s.out, "  %s%s%s\n", config.Gray, text, config.Reset)
	if s.tty && time.Since(s.created) >= spinnerDelay {
		s.draw()
	}
}

// Stop removes the spinner's line. It is safe to call more than once.
func (s *spinner) Stop() {
	s.mu.Lock()
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	s.mu.Unlock()
	<-s.done
}

func (s *spinner) draw() {
	elapsed := time.Since(s.created)
	verb := s.verbs[int(elapsed/verbEvery)%len(s.verbs)]
	line := fmt.Sprintf("\r\033[K  %s%s%s %s…", spinnerColor, spinnerFrames[s.frame%len(spinnerFrames)], config.Reset, msg(s.lang, verb[0], verb[1]))
	if secs := int(elapsed.Seconds()); secs >= 1 {
		line += fmt.Sprintf(" %s(%s)%s", config.Gray, fmt.Sprintf(msg(s.lang, "%ds", "%d s"), secs), config.Reset)
	}
	_, _ = fmt.Fprint(s.out, line)
	s.drawn = true
}

func (s *spinner) clear() {
	if s.drawn {
		_, _ = fmt.Fprint(s.out, "\r\033[K")
		s.drawn = false
	}
}

// isTerminal reports whether f is an interactive terminal that can redraw a
// line in place.
func isTerminal(f *os.File) bool {
	if t := strings.ToLower(os.Getenv("TERM")); t == "dumb" {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
