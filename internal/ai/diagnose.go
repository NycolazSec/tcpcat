package ai

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NycolazSec/tcpcat/internal/scan"
	"github.com/NycolazSec/tcpcat/internal/service"
)

// How a scan went, and what got in its way. A port that does not answer is
// not one fact but several: the machine said the port is closed (RST), a
// firewall threw the packet away (no answer), a firewall refused it out loud
// (ICMP), or something accepted the connection and then said nothing. Read
// together, host by host, they say what filters the machine, and whether the
// scanner itself was blocked.
//
// scanStory reads that from the scan alone. In a thorough analysis,
// diagnose then checks it on the network: is what was open still open, does
// a block lift after a pause, how long does a silent service take to speak.

// Timings of the thorough diagnosis. Variables so tests can shorten them.
var (
	diagDialTimeout = 3 * time.Second
	diagCoolDown    = 15 * time.Second
	diagBannerWait  = 8 * time.Second
	diagSlowGap     = time.Second // between the slow, one-at-a-time probes
)

// diagMaxHosts bounds the network checks of one analysis.
const diagMaxHosts = 8

// speaksFirst are the protocols whose server sends a banner before the
// client says anything: silence there means something.
var speaksFirst = map[string]bool{"ssh": true, "ftp": true, "smtp": true, "pop3": true, "imap": true, "telnet": true, "mysql": true, "vnc": true}

type portCounts struct {
	open, closed, dropped, rejected int
	closedPorts, rejectedPorts      []int
	maxOpenMs                       float64
	droppedMs                       []float64
}

// rejectedReason reports a refusal announced by an ICMP error: a firewall
// that rejects instead of dropping, or a router with no way there.
func rejectedReason(reason string) bool {
	r := strings.ToLower(reason)
	return strings.Contains(r, "icmp") || strings.Contains(r, "unreachable") ||
		strings.Contains(r, "no route") || strings.Contains(r, "prohibited")
}

func countPorts(results []scan.TargetResult) (map[string]*portCounts, []string) {
	counts := map[string]*portCounts{}
	var order []string
	for _, r := range results {
		c := counts[r.IP]
		if c == nil {
			c = &portCounts{}
			counts[r.IP] = c
			order = append(order, r.IP)
		}
		switch {
		case isOpen(r.State):
			c.open++
			c.maxOpenMs = max(c.maxOpenMs, r.LatencyMs)
		case strings.EqualFold(r.State, "CLOSED"):
			c.closed++
			c.closedPorts = append(c.closedPorts, r.Port)
		case rejectedReason(r.Reason):
			c.rejected++
			c.rejectedPorts = append(c.rejectedPorts, r.Port)
		default:
			c.dropped++
			c.droppedMs = append(c.droppedMs, r.LatencyMs)
		}
	}
	return counts, order
}

// scanStory tells, host by host, what answered and what filters the
// machine, from the scan's own results.
func scanStory(results []scan.TargetResult, lang string) []string {
	counts, order := countPorts(results)
	var story []string
	for _, h := range order {
		c := counts[h]
		story = append(story, h+tr(lang, "colon")+countLine(lang, c)+".")
		switch {
		case c.open+c.closed+c.rejected == 0:
			// Nothing answered: the alert says what that means.
		case c.rejected > 0:
			story = append(story, tr(lang, "story-reject", joinPorts(c.rejectedPorts)))
		case c.closed > 0 && c.dropped == 0:
			story = append(story, tr(lang, "story-no-firewall"))
		case c.closed > 0:
			story = append(story, tr(lang, "story-partial", joinPorts(c.closedPorts)))
		case c.open > 0 && c.dropped > 0:
			story = append(story, tr(lang, "story-whitelist"))
		}
		// Open ports answering close to the timeout: the ports that did not
		// answer in time may only be slow.
		if timeout := median(c.droppedMs); len(c.droppedMs) >= 2 && timeout > 0 && c.open > 0 && c.maxOpenMs > 0.6*timeout {
			story = append(story, tr(lang, "story-slow", fmt.Sprintf("%.0f", c.maxOpenMs), fmt.Sprintf("%.0f", timeout)))
		}
	}
	return story
}

func countLine(lang string, c *portCounts) string {
	var parts []string
	add := func(n int, en, fr, frSuffix string) {
		if n == 0 {
			return
		}
		if lang == "fr" {
			word := fr
			if n > 1 {
				word += "s"
			}
			parts = append(parts, fmt.Sprintf("%d %s%s", n, word, frSuffix))
			return
		}
		parts = append(parts, fmt.Sprintf("%d %s", n, en))
	}
	add(c.open, "open", "ouvert", "")
	add(c.closed, "closed (RST)", "fermé", " (RST)")
	add(c.dropped, "dropped silently", "filtré", " en silence")
	add(c.rejected, "rejected (ICMP)", "refusé", " par ICMP")
	return strings.Join(parts, ", ")
}

func joinPorts(ports []int) string {
	sort.Ints(ports)
	var s []string
	for i, p := range ports {
		if i == 8 {
			s = append(s, "…")
			break
		}
		s = append(s, strconv.Itoa(p))
	}
	return strings.Join(s, ", ")
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

func seconds(lang string, d time.Duration) string {
	s := strconv.FormatFloat(d.Seconds(), 'f', 1, 64)
	if lang == "fr" {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s + " s"
}

// diagnose checks the scan's story on the network, read-only, and returns
// the results with the banners it obtained, what it found, and the alerts.
func (a *Analyzer) diagnose(results []scan.TargetResult, lang string, d Diagnoser, progress func(string)) ([]scan.TargetResult, []string, []string) {
	results = append([]scan.TargetResult(nil), results...)
	say := func(s string) {
		if progress != nil {
			progress(s)
		}
	}
	var story, alerts []string
	blind := map[string]bool{}
	for _, h := range blindHosts(results) {
		blind[h.host] = true
	}
	_, order := countPorts(results)
	checked := 0
	for _, h := range order {
		var open, scanned []int
		for _, r := range results {
			if r.IP != h {
				continue
			}
			scanned = append(scanned, r.Port)
			if isOpen(r.State) {
				open = append(open, r.Port)
			}
		}
		if !blind[h] && len(open) == 0 {
			continue
		}
		if checked++; checked > diagMaxHosts {
			break
		}

		if blind[h] {
			s, al := a.diagnoseBlind(h, scanned, lang, d, say)
			story, alerts = append(story, s...), append(alerts, al...)
			continue
		}

		// Is what answered during the scan still answering?
		probe := open[:min(3, len(open))]
		say(tr(lang, "diag-recheck", h))
		states := dialAll(d, h, probe)
		var gone []int
		for i, p := range probe {
			if states[i] == "filtered" {
				gone = append(gone, p)
			}
		}
		if len(gone) == len(probe) {
			alerts = append(alerts, tr(lang, "diag-blocked-now", h, joinPorts(gone)))
			say(tr(lang, "diag-wait", int(diagCoolDown.Seconds())))
			time.Sleep(diagCoolDown)
			if d.Dial(h, probe[0], diagDialTimeout) == "open" {
				story = append(story, tr(lang, "diag-unblocked", int(diagCoolDown.Seconds()), probe[0]))
			} else {
				alerts = append(alerts, tr(lang, "diag-still-blocked", int(diagCoolDown.Seconds())))
				continue
			}
		} else {
			story = append(story, tr(lang, "diag-still-open", h))
		}

		// How long do the silent services take to speak?
		var silent []int
		for _, r := range results {
			if r.IP == h && isOpen(r.State) && isSilent(r) {
				silent = append(silent, r.Port)
			}
		}
		if len(silent) > 4 {
			silent = silent[:4]
		}
		if len(silent) > 0 {
			say(tr(lang, "diag-banner-wait", h))
		}
		type heard struct {
			connected bool
			delay     time.Duration
			data      string
		}
		got := make([]heard, len(silent))
		var wg sync.WaitGroup
		for i, p := range silent {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, delay, data := d.FirstBytes(h, p, diagBannerWait)
				got[i] = heard{c, delay, data}
			}()
		}
		wg.Wait()
		for i, p := range silent {
			g := got[i]
			banner := service.SanitizeBanner(strings.TrimSpace(g.data))
			switch {
			case !g.connected:
			case banner != "":
				line := tr(lang, "diag-banner-late", p, seconds(lang, g.delay))
				if strings.HasPrefix(banner, "SSH-") {
					line += " " + tr(lang, "diag-ssh-slow-hint")
				}
				story = append(story, line)
				for j := range results {
					if results[j].IP == h && results[j].Port == p {
						results[j].Banner = banner
					}
				}
			case a.speaksFirst(p) != "":
				story = append(story, tr(lang, "diag-banner-none", p, seconds(lang, diagBannerWait), a.speaksFirst(p), a.speaksFirst(p)))
			}
		}
	}
	return results, story, alerts
}

// diagnoseBlind looks into a host on which nothing answered: one slow
// connection at a time, then once more after a pause.
func (a *Analyzer) diagnoseBlind(h string, scanned []int, lang string, d Diagnoser, say func(string)) (story, alerts []string) {
	ports := commonFirst(scanned)
	if len(ports) == 0 {
		return nil, nil
	}
	say(tr(lang, "diag-slow-probe", h))
	for i, p := range ports {
		if i > 0 {
			time.Sleep(diagSlowGap)
		}
		if st := d.Dial(h, p, diagDialTimeout); st != "filtered" {
			return []string{tr(lang, "diag-blind-answers", h, p)}, nil
		}
	}
	say(tr(lang, "diag-wait", int(diagCoolDown.Seconds())))
	time.Sleep(diagCoolDown)
	if st := d.Dial(h, ports[0], diagDialTimeout); st != "filtered" {
		return []string{tr(lang, "diag-unblocked", int(diagCoolDown.Seconds()), ports[0])}, nil
	}
	return nil, []string{tr(lang, "diag-blind-dead", h, int(diagCoolDown.Seconds()))}
}

// commonFirst picks up to three of the scanned ports, the ones most hosts
// leave open first.
func commonFirst(scanned []int) []int {
	rank := map[int]int{443: 1, 80: 2, 22: 3}
	s := append([]int(nil), scanned...)
	sort.SliceStable(s, func(i, j int) bool {
		ri, rj := rank[s[i]], rank[s[j]]
		if ri == 0 {
			ri = 99
		}
		if rj == 0 {
			rj = 99
		}
		return ri < rj
	})
	return s[:min(3, len(s))]
}

func dialAll(d Diagnoser, h string, ports []int) []string {
	states := make([]string, len(ports))
	var wg sync.WaitGroup
	for i, p := range ports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			states[i] = d.Dial(h, p, diagDialTimeout)
		}()
	}
	wg.Wait()
	return states
}

// speaksFirst names the protocol expected on a port when its server should
// speak first, or returns "".
func (a *Analyzer) speaksFirst(port int) string {
	for _, s := range a.Dict.ByPort(port) {
		if speaksFirst[s.Protocol()] {
			if p := a.Dict.Get(s.Protocol()); p != nil {
				return strings.ToUpper(p.ID)
			}
		}
	}
	return ""
}
