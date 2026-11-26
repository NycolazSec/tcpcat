// Package ai is tcpcat's own AI. It reads a scan and says, in plain French
// or English, what is exposed, how serious it is, why, and what to do.
//
// It runs offline, inside the binary, from three parts:
//
//   - a dictionary (kb): what each network service is, whether it belongs on
//     the internet, why exposing it is dangerous and how to stop;
//   - a trained model (model): names the service behind a port from its
//     banner, even truncated, noisy or on an unusual port, and says how sure
//     it is;
//   - this reasoning step: joins the scan, the dictionary and the model into
//     findings, each with the evidence it rests on.
//
// The rule it follows: no statement without evidence from the scan. When the
// identification rests only on a port number, the finding says so.
package ai

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/NycolazSec/tcpcat/internal/ai/kb"
	"github.com/NycolazSec/tcpcat/internal/ai/model"
	"github.com/NycolazSec/tcpcat/internal/scan"
	"github.com/NycolazSec/tcpcat/internal/service"
	"github.com/NycolazSec/tcpcat/internal/vuln"
)

// Vantages: where the scan ran from.
const (
	Internet = "internet"
	Internal = "internal"
)

// Verdicts, from worst to best.
const (
	Fix    = "fix"    // should not be reachable from here, or exploited flaw
	Review = "review" // acceptable if limited or hardened
	OK     = "ok"     // expected
)

// Options tune an analysis.
type Options struct {
	Lang    string // "fr" or "en"
	Vantage string // Internet (default) or Internal
	// FromClusterNode says the scan ran from a Kubernetes node, which the
	// cluster's firewall may trust more than the internet.
	FromClusterNode bool
}

// Identification is what the AI believes runs behind a port, and why.
type Identification struct {
	ID           string   `json:"id,omitempty"` // dictionary ID, empty when unknown
	Name         string   `json:"name"`
	Source       string   `json:"source"` // "probe", "model", "port" or "none"
	Confidence   float64  `json:"confidence"`
	Alternatives []string `json:"alternatives,omitempty"`
	Note         string   `json:"note,omitempty"`    // e.g. the detector named it differently
	Refined      string   `json:"refined,omitempty"` // the protocol-level answer the port narrowed down
}

// Finding is one open port, judged.
type Finding struct {
	Host     string         `json:"host"`
	Port     int            `json:"port"`
	Service  Identification `json:"service"`
	Exposure string         `json:"exposure,omitempty"` // dictionary: public, restricted, private
	Severity string         `json:"severity"`
	Verdict  string         `json:"verdict"`
	Title    string         `json:"title"`
	Why      string         `json:"why,omitempty"`
	Fix      string         `json:"fix,omitempty"`
	Evidence []string       `json:"evidence"`
	Checks   []Check        `json:"checks,omitempty"` // deep analysis only
}

// Report is the result of an analysis.
type Report struct {
	Vantage string `json:"vantage"`
	Lang    string `json:"lang"`
	// Alerts are about the scan as a whole: what it cannot tell, and why.
	Alerts   []string  `json:"alerts,omitempty"`
	Findings []Finding `json:"findings"`
	ToFix    int       `json:"to_fix"`
	ToReview int       `json:"to_review"`
	Fine     int       `json:"ok"`
	Summary  string    `json:"summary"`
}

// Analyzer holds the dictionary and model an analysis uses.
type Analyzer struct {
	Dict  *kb.Dictionary
	Model *model.Model
}

// New returns an Analyzer with the dictionary and model built into tcpcat.
func New() (*Analyzer, error) {
	m, err := model.Default()
	if err != nil {
		return nil, err
	}
	return &Analyzer{Dict: kb.Default(), Model: m}, nil
}

// Analyze judges every open port of a scan.
func (a *Analyzer) Analyze(results []scan.TargetResult, opt Options) Report {
	if opt.Lang != "fr" {
		opt.Lang = "en"
	}
	if opt.Vantage != Internal {
		opt.Vantage = Internet
	}
	rep := Report{Vantage: opt.Vantage, Lang: opt.Lang}
	for _, h := range blindHosts(results) {
		rep.Alerts = append(rep.Alerts, tr(opt.Lang, "alert-blind", h.host, h.tested))
	}
	for _, h := range muteHosts(results) {
		rep.Alerts = append(rep.Alerts, tr(opt.Lang, "alert-mute", h.host, h.tested))
	}
	medians := hostLatencyMedians(results)
	for _, r := range results {
		if !isOpen(r.State) {
			continue
		}
		f := a.judge(r, opt)
		if m := medians[r.IP]; isMiddleboxAnswer(r.LatencyMs, m) {
			a.markMiddlebox(&f, r, m, opt.Lang)
		}
		rep.Findings = append(rep.Findings, f)
	}
	for _, f := range rep.Findings {
		if contains(f.Evidence, tr(opt.Lang, "ev-cluster-node")) {
			rep.Alerts = append(rep.Alerts, tr(opt.Lang, "alert-cluster-node"))
			break
		}
	}
	sortFindings(rep.Findings)
	for _, f := range rep.Findings {
		switch f.Verdict {
		case Fix:
			rep.ToFix++
		case Review:
			rep.ToReview++
		default:
			rep.Fine++
		}
	}
	rep.Summary = tr(opt.Lang, "summary", rep.ToFix, rep.ToReview, rep.Fine)
	return rep
}

type blindHost struct {
	host   string
	tested int
}

// blindHosts are the hosts on which no port answered at all: every port
// tested filtered (a lone closed one aside). That is not good news, it is
// no news: the machine is off, or something drops the scanner's packets.
func blindHosts(results []scan.TargetResult) []blindHost {
	type count struct{ open, closed, filtered int }
	counts := map[string]*count{}
	var order []string
	for _, r := range results {
		c := counts[r.IP]
		if c == nil {
			c = &count{}
			counts[r.IP] = c
			order = append(order, r.IP)
		}
		switch strings.ToUpper(r.State) {
		case "OPEN":
			c.open++
		case "CLOSED":
			c.closed++
		default:
			c.filtered++
		}
	}
	var out []blindHost
	for _, h := range order {
		c := counts[h]
		if tested := c.open + c.closed + c.filtered; c.open == 0 && c.filtered >= 3 && c.closed <= 1 {
			out = append(out, blindHost{h, tested})
		}
	}
	return out
}

// muteHosts are the hosts whose open ports (two or more) all accepted a
// connection and then said nothing to service detection: more likely
// something on the path than several silent services. tested is the number
// of open ports.
func muteHosts(results []scan.TargetResult) []blindHost {
	open, silent := map[string]int{}, map[string]int{}
	var order []string
	for _, r := range results {
		if !isOpen(r.State) {
			continue
		}
		if open[r.IP] == 0 {
			order = append(order, r.IP)
		}
		open[r.IP]++
		if isSilent(r) {
			silent[r.IP]++
		}
	}
	var out []blindHost
	for _, h := range order {
		if open[h] >= 2 && silent[h] == open[h] {
			out = append(out, blindHost{h, open[h]})
		}
	}
	return out
}

// isSilent reports a port where service detection ran and got nothing back.
func isSilent(r scan.TargetResult) bool {
	return strings.EqualFold(strings.TrimSpace(r.Service), "unknown") && strings.TrimSpace(r.Banner) == ""
}

func isOpen(state string) bool {
	// open|filtered (UDP without a reply) says nothing about what listens.
	return strings.EqualFold(state, "OPEN")
}

func verdictRank(v string) int {
	switch v {
	case Fix:
		return 2
	case Review:
		return 1
	}
	return 0
}

// Identify decides what runs behind one port: a protocol probe's answer
// first (it spoke the protocol), then the model reading the banner, then the
// dictionary's port conventions.
func (a *Analyzer) Identify(r scan.TargetResult, lang string) Identification {
	id := a.identify(r)
	if s := a.Dict.Get(id.ID); s != nil {
		id = a.refineByPort(id, s, r.Port)
		id.Name = a.Dict.Get(id.ID).DisplayName(lang)
	}
	for i, alt := range id.Alternatives {
		if s := a.Dict.ByName(alt); s != nil {
			id.Alternatives[i] = s.DisplayName(lang)
		}
	}
	return id
}

// refineByPort narrows a protocol-level answer ("SSH", "HTTP") with the
// dictionary's port conventions: SSH on 2022 is Pterodactyl's SFTP, HTTP on
// 8080 is a web service on an alternate port. A product-level answer
// (OpenSSH, nginx) already says more than the port could.
func (a *Analyzer) refineByPort(id Identification, s *kb.Service, port int) Identification {
	if s.ID != s.Protocol() {
		return id
	}
	// "HTTP" is a transport as much as a service: on 10250 it is the
	// kubelet, on 2375 the Docker API. Any HTTP-speaking service of the
	// port is a more specific answer than "a web server".
	web := s.Protocol() == "http" || s.Protocol() == "https"
	var specific []*kb.Service
	for _, c := range a.Dict.ByPort(port) {
		if c.ID != s.ID && (c.Protocol() == s.Protocol() || web && c.SpeaksHTTP()) {
			specific = append(specific, c)
		}
	}
	if len(specific) == 0 {
		return id
	}
	sort.SliceStable(specific, func(i, j int) bool { return stricter(specific[i], specific[j]) })
	id.Refined = s.ID
	id.ID = specific[0].ID
	if id.Confidence > 0.8 {
		id.Confidence = 0.8
	}
	for _, c := range specific[1:] {
		id.Alternatives = append(id.Alternatives, c.ID)
	}
	return id
}

func (a *Analyzer) identify(r scan.TargetResult) Identification {
	detected := strings.ToLower(strings.TrimSpace(r.Service))
	portName, _ := service.IdentifyStoredBanner("", r.Port)
	sigName, fromBanner := service.IdentifyStoredBanner(r.Banner, r.Port)
	// The detector's name is evidence of its own unless it is merely the
	// port's conventional name, which says nothing about what answered.
	probed := detected != "" && detected != "unknown" && detected != "ssl/unknown" &&
		(detected != portName || fromBanner && sigName == detected)

	var guess model.Guess
	if strings.TrimSpace(r.Banner) != "" && a.Model != nil {
		guesses := a.Model.Classify(r.Banner, r.Port)
		guess = guesses[0]
		// Unsure which product, sure of the kind of service: say the kind.
		if fam := a.Families(guesses); guess.P < 0.5 && len(fam) > 0 && fam[0].P >= 0.5 {
			guess = fam[0]
		}
	}
	guessed := a.Dict.Get(guess.ID)

	if probed {
		if s := a.Dict.ByName(detected); s != nil {
			id := Identification{ID: s.ID, Name: s.Name, Source: "probe", Confidence: 0.99}
			// A model that strongly disagrees on the kind of service is
			// worth showing, not overriding: the probe spoke the protocol.
			if guessed != nil && guess.P >= 0.9 && guessed.Protocol() != s.Protocol() {
				id.Note = guessed.Name
			}
			return id
		}
	}
	if guessed != nil && guess.P >= 0.5 {
		id := Identification{ID: guessed.ID, Name: guessed.Name, Source: "model", Confidence: round2(guess.P)}
		if detected != "" && detected != "unknown" {
			if s := a.Dict.ByName(detected); s == nil || s.Protocol() != guessed.Protocol() {
				id.Note = detected
			}
		}
		return id
	}
	if probed {
		// Named by a probe, but missing from the dictionary.
		return Identification{Name: detected, Source: "probe", Confidence: 0.9}
	}
	cands := a.Dict.ByPort(r.Port)
	if len(cands) == 0 {
		cands = a.Dict.ByUDPPort(r.Port)
	}
	if len(cands) == 0 {
		return Identification{Name: "?", Source: "none"}
	}
	// Several services share this port: assume the one that would matter
	// most, and say which others it could be.
	sort.SliceStable(cands, func(i, j int) bool { return stricter(cands[i], cands[j]) })
	id := Identification{ID: cands[0].ID, Name: cands[0].Name, Source: "port", Confidence: 0.5}
	if len(cands) > 1 {
		id.Confidence = 0.3
		for _, c := range cands[1:] {
			id.Alternatives = append(id.Alternatives, c.ID)
		}
	}
	return id
}

// Families adds up the model's guesses by kind of service (every FTP
// server is FTP, every web server HTTP), most likely first. Each family is
// named by its dictionary entry.
func (a *Analyzer) Families(guesses []model.Guess) []model.Guess {
	sum := map[string]float64{}
	for _, g := range guesses {
		s := a.Dict.Get(g.ID)
		if s == nil {
			continue
		}
		fam := s.Protocol()
		if s.SpeaksHTTP() {
			fam = "http"
		}
		if a.Dict.Get(fam) != nil {
			sum[fam] += g.P
		}
	}
	out := make([]model.Guess, 0, len(sum))
	for id, p := range sum {
		out = append(out, model.Guess{ID: id, P: p})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].P != out[j].P {
			return out[i].P > out[j].P
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// stricter orders services by how much their exposure would matter.
func stricter(a, b *kb.Service) bool {
	rank := map[string]int{kb.Public: 0, kb.Restricted: 1, kb.Private: 2}
	if rank[a.Exposure] != rank[b.Exposure] {
		return rank[a.Exposure] > rank[b.Exposure]
	}
	return kb.SeverityRank(a.Risk) > kb.SeverityRank(b.Risk)
}

func (a *Analyzer) judge(r scan.TargetResult, opt Options) Finding {
	lang := opt.Lang
	id := a.Identify(r, lang)
	f := Finding{Host: r.IP, Port: r.Port, Service: id}
	f.Evidence = append(f.Evidence, tr(lang, "ev-open", r.Port, localReason(lang, reason(r))))
	if b := strings.TrimSpace(r.Banner); b != "" {
		f.Evidence = append(f.Evidence, tr(lang, "ev-banner", b))
	}
	switch id.Source {
	case "probe":
		probed := id.Name
		if p := a.Dict.Get(id.Refined); p != nil {
			probed = p.DisplayName(lang)
		}
		f.Evidence = append(f.Evidence, tr(lang, "ev-probe", probed))
	case "model":
		f.Evidence = append(f.Evidence, tr(lang, "ev-model", id.Name, int(100*id.Confidence)))
	case "port":
		f.Evidence = append(f.Evidence, tr(lang, "ev-port", r.Port, id.Name))
	}
	if id.Refined != "" {
		f.Evidence = append(f.Evidence, tr(lang, "ev-refined", r.Port, id.Name))
	}
	if id.Note != "" {
		f.Evidence = append(f.Evidence, tr(lang, "ev-disagree", id.Note))
	}
	if len(id.Alternatives) > 0 {
		f.Evidence = append(f.Evidence, tr(lang, "ev-alt", strings.Join(id.Alternatives, ", ")))
	}

	s := a.Dict.Get(id.ID)
	if s == nil {
		f.Severity, f.Verdict = "low", Review
		if opt.Vantage == Internal {
			f.Severity, f.Verdict = "info", OK
		}
		f.Title = tr(lang, "title-unknown", r.Port)
		if id.Source == "probe" {
			f.Title = tr(lang, "title-unlisted", id.Name, r.Port)
		}
		f.Why = tr(lang, "why-unknown")
		f.Fix = tr(lang, "fix-unknown", r.Port)
		a.addVulns(&f, r, lang)
		return f
	}
	// A website on a port other than 80/443 is rarely meant for the public:
	// judge it like any web service on an alternate port.
	if (s.Protocol() == "http" || s.Protocol() == "https") && s.Exposure == kb.Public && r.Port != 80 && r.Port != 443 && !hasPort(s.Ports, r.Port) {
		if alt := a.Dict.Get("http-alt"); alt != nil {
			c := *s
			c.Exposure, c.Risk, c.Why, c.Hint = alt.Exposure, alt.Risk, alt.Why, alt.Hint
			s = &c
		}
	}
	f.Exposure = s.Exposure
	name := id.Name
	hedged := len(id.Alternatives) > 0 && (id.Source == "port" || id.Refined != "")

	// Exposure, judged from where the scan ran.
	switch {
	case opt.Vantage == Internal:
		f.Severity, f.Verdict = "info", OK
		f.Title = tr(lang, "title-internal", name)
		if s.Exposure == kb.Private && s.Risk == "critical" {
			f.Severity, f.Verdict = "low", Review
			f.Title = tr(lang, "title-internal-check", name)
			f.Why = s.Why.In(lang)
			f.Fix = joinSentences(tr(lang, "fix-internal"), s.Hint.In(lang))
		}
	case s.Exposure == kb.Public:
		f.Severity, f.Verdict = "info", OK
		f.Title = tr(lang, "title-public", name)
		f.Why = s.Why.In(lang)
	case s.Exposure == kb.Restricted:
		f.Severity, f.Verdict = s.Risk, Review
		f.Title = tr(lang, "title-restricted", name)
		f.Why = s.Why.In(lang)
		f.Fix = joinSentences(tr(lang, "fix-restricted", r.Port), s.Hint.In(lang))
	default:
		f.Severity, f.Verdict = s.Risk, Fix
		f.Title = tr(lang, "title-private", name)
		f.Why = s.Why.In(lang)
		f.Fix = joinSentences(tr(lang, "fix-private", r.Port), s.Hint.In(lang))
	}
	// A port-only guess among several services is not proof: say less.
	if id.Source == "port" && len(id.Alternatives) > 0 && kb.SeverityRank(f.Severity) > kb.SeverityRank("medium") {
		f.Severity = "medium"
	}
	// Service detection ran and nothing answered: the port's number is all
	// there is to go on.
	silent := isSilent(r)
	if silent {
		f.Evidence = append(f.Evidence, tr(lang, "ev-silent"))
	}
	// Seen from a node of the cluster, a cluster port may be open for that
	// node only.
	if opt.FromClusterNode && opt.Vantage == Internet && a.inGroup(s, "cluster") && f.Verdict != OK {
		f.Verdict = Review
		if kb.SeverityRank(f.Severity) > kb.SeverityRank("medium") {
			f.Severity = "medium"
		}
		f.Evidence = append(f.Evidence, tr(lang, "ev-cluster-node"))
		hedged = true
	}
	if hedged || silent && id.Source == "port" {
		f.Title += tr(lang, "to-confirm")
	}
	f.Evidence = append(f.Evidence, postureNotes(r, lang)...)
	if s.IsInsecure() && kb.SeverityRank(f.Severity) < kb.SeverityRank("medium") {
		f.Severity = "medium"
		if f.Verdict == OK {
			f.Verdict = Review
		}
		f.Evidence = append(f.Evidence, tr(lang, "ev-cleartext"))
	}
	a.addVulns(&f, r, lang)
	return f
}

// inGroup reports whether a service descends from the dictionary entry group.
func (a *Analyzer) inGroup(s *kb.Service, group string) bool {
	for i := 0; s != nil && i < 8; i++ {
		if s.ID == group || s.Parent == group {
			return true
		}
		s = a.Dict.Get(s.Parent)
	}
	return false
}

// addVulns raises a finding for the vulnerabilities the scan correlated.
func (a *Analyzer) addVulns(f *Finding, r scan.TargetResult, lang string) {
	var kev []string
	worst := ""
	// Flaws of a product's client tools (OpenSSH's ssh, scp, sftp) do not
	// threaten the server that was scanned: keep them out of the verdict.
	var applicable []vuln.Vulnerability
	clientSide := 0
	for _, v := range r.Vulnerabilities {
		if v.Applicability != "" {
			continue // its title names a precondition the scan has no evidence of
		}
		if isClientSide(f.Service.ID, v.Title) {
			clientSide++
			continue
		}
		applicable = append(applicable, v)
	}
	shown := append([]vuln.Vulnerability(nil), applicable...)
	sort.SliceStable(shown, func(i, j int) bool {
		if shown[i].KnownExploited != shown[j].KnownExploited {
			return shown[i].KnownExploited
		}
		return shown[i].CVSS > shown[j].CVSS
	})
	var top []string
	for _, v := range shown {
		if len(top) < 3 && (v.KnownExploited || v.CVSS >= 7) {
			top = append(top, fmt.Sprintf("%s (CVSS %.1f)", v.ID, v.CVSS))
		}
	}
	maxCVSS := 0.0
	for _, v := range applicable {
		maxCVSS = max(maxCVSS, v.CVSS)
		sev := "low"
		switch {
		case v.KnownExploited:
			sev = "critical"
			kev = append(kev, v.ID)
		case v.CVSS >= 9 && (v.EPSS == 0 || v.EPSS >= 0.1):
			sev = "high"
		case v.CVSS >= 7:
			sev = "medium"
		}
		if kb.SeverityRank(sev) > kb.SeverityRank(worst) {
			worst = sev
		}
	}
	if clientSide > 0 {
		f.Evidence = append(f.Evidence, tr(lang, "ev-client-side", clientSide))
	}
	if worst == "" {
		return
	}
	f.Evidence = append(f.Evidence, tr(lang, "ev-vulns", len(applicable), strings.Join(top, ", ")))
	if len(kev) > 0 {
		f.Evidence = append(f.Evidence, tr(lang, "ev-kev", strings.Join(kev, ", ")))
	}
	if kb.SeverityRank(worst) > kb.SeverityRank(f.Severity) {
		f.Severity = worst
	}
	if worst == "medium" && f.Verdict == OK {
		f.Verdict = Review
		f.Title = tr(lang, "title-vuln-medium", f.Service.Name)
		f.Why = tr(lang, "why-vuln", score(lang, maxCVSS))
		f.Fix = tr(lang, "fix-update", f.Service.Name)
	}
	if worst == "critical" || worst == "high" {
		f.Verdict = Fix
		if len(kev) > 0 {
			f.Title = tr(lang, "title-kev", f.Service.Name)
		} else if f.Exposure == kb.Public || f.Exposure == kb.Restricted {
			f.Title = tr(lang, "title-vuln", f.Service.Name)
		}
		f.Fix = joinSentences(tr(lang, "fix-update", f.Service.Name), f.Fix)
		if f.Why == "" || f.Exposure == kb.Public || f.Exposure == kb.Restricted {
			f.Why = joinSentences(tr(lang, "why-vuln", score(lang, maxCVSS)), f.Why)
		}
	}
}

// clientTool matches vulnerability titles about a product's client programs
// rather than its server ("scp in OpenSSH before 10.4 ...").
var clientTool = map[string]*regexp.Regexp{
	"ssh": regexp.MustCompile(`(?i)^\s*(ssh|scp|sftp|ssh-agent|ssh-add|ssh-keygen|ssh-keyscan|ssh-pkcs11-helper)\s+(in|of|from)\s+openssh\b`),
}

func isClientSide(id, title string) bool {
	s := kb.Default().Get(id)
	if s == nil {
		return false
	}
	re := clientTool[s.Protocol()]
	return re != nil && re.MatchString(title)
}

func reason(r scan.TargetResult) string {
	if r.Reason != "" {
		return r.Reason
	}
	return r.State
}

func joinSentences(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

func round2(p float64) float64 { return float64(int(p*100+0.5)) / 100 }

// hostLatencyMedians returns, per host, the median reply time of its open
// ports.
func hostLatencyMedians(results []scan.TargetResult) map[string]float64 {
	by := map[string][]float64{}
	for _, r := range results {
		if isOpen(r.State) && r.LatencyMs > 0 {
			by[r.IP] = append(by[r.IP], r.LatencyMs)
		}
	}
	out := map[string]float64{}
	for h, ls := range by {
		if len(ls) < 3 {
			continue // too few ports to call one of them abnormal
		}
		sort.Float64s(ls)
		out[h] = ls[len(ls)/2]
	}
	return out
}

// isMiddleboxAnswer: a port that answers several times faster than the rest
// of its host, on a distant host, was almost certainly answered by something
// on the network path (a home router's FTP helper, a transparent proxy, a
// firewall that accepts every connection) rather than by the host.
func isMiddleboxAnswer(latency, median float64) bool {
	return median >= 20 && latency > 0 && latency < 15 && latency < median/4
}

func (a *Analyzer) markMiddlebox(f *Finding, r scan.TargetResult, median float64, lang string) {
	f.Evidence = append(f.Evidence, tr(lang, "ev-middlebox", r.LatencyMs, median))
	f.Severity, f.Verdict = "info", Review
	f.Title = tr(lang, "title-middlebox", r.Port)
	f.Why = tr(lang, "why-middlebox")
	f.Fix = tr(lang, "fix-middlebox")
}

// postureNotes are the probes' own warnings (weak SSH algorithms, a
// self-signed certificate), at most two, as supporting evidence.
func postureNotes(r scan.TargetResult, lang string) []string {
	var notes []string
	if r.SSHPosture != nil {
		notes = append(notes, r.SSHPosture.Warnings...)
	}
	if r.TLS != nil {
		notes = append(notes, r.TLS.Warnings...)
	}
	notes = append(notes, r.Findings...)
	for i, n := range notes {
		n = localNote(lang, n)
		if r := []rune(n); len(r) > 70 {
			n = strings.TrimSpace(string(r[:67])) + "…"
		}
		notes[i] = n
	}
	if len(notes) == 0 {
		return nil
	}
	if len(notes) > 2 {
		notes = append(notes[:2:2], tr(lang, "ev-more", len(notes)-2))
	}
	return []string{tr(lang, "ev-posture", strings.Join(notes, "; "))}
}

// score writes a CVSS score the way the language does: 7.8 or 7,8.
func score(lang string, v float64) string {
	s := fmt.Sprintf("%.1f", v)
	if lang == "fr" {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s
}

func hasPort(ports []int, p int) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}
