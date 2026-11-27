package ai

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/NycolazSec/tcpcat/internal/ai/kb"
	"github.com/NycolazSec/tcpcat/internal/scan"
)

// A deep analysis takes the time a careful admin would. After the quick
// verdicts it checks its own hypotheses with read-only follow-up probes (does
// SSH accept passwords? does the kubelet answer anonymous requests? is that
// really Wings on 8080?), works out what the machine is, says what is going
// well, and ends with an ordered plan.

// Check kinds.
const (
	CheckOK    = "ok"    // verified, and fine
	CheckIssue = "issue" // verified, and something to fix
	CheckNote  = "note"  // verified, worth knowing
)

// Check is one verification run on a finding.
type Check struct {
	Kind     string `json:"kind"`
	Text     string `json:"text"`
	Severity string `json:"severity,omitempty"` // issues only
	Fix      string `json:"fix,omitempty"`      // issues only
	// Lines are the exact lines the fix adds to a configuration file, to
	// copy as they are.
	Lines []string `json:"lines,omitempty"`
}

// Action is one step of the plan.
type Action struct {
	Severity string `json:"severity"`
	Where    string `json:"where"`
	Text     string `json:"text"`
}

// DeepReport is a Report plus what the deep analysis worked out.
type DeepReport struct {
	Report
	Profile []string `json:"profile"`
	Good    []string `json:"good"`
	Plan    []Action `json:"plan"`
}

// Deep runs the analysis, the follow-up checks, and the synthesis. progress,
// when not nil, is told what is being checked.
func (a *Analyzer) Deep(results []scan.TargetResult, opt Options, p Prober, progress func(string)) DeepReport {
	opt.Lang = Lang(opt.Lang)
	// First, how the scan went: is the scanner blocked, are the silent
	// services only slow? The banners this brings in feed the analysis.
	var diagStory, diagAlerts []string
	blocked := map[string]bool{}
	if d, ok := p.(Diagnoser); ok {
		results, diagStory, diagAlerts, blocked = a.diagnose(results, opt.Lang, d, progress)
	}
	rep := a.Analyze(results, opt)
	rep.Story = append(rep.Story, diagStory...)
	rep.Alerts = append(rep.Alerts, diagAlerts...)
	lang := rep.Lang
	byAddr := map[string]scan.TargetResult{}
	for _, r := range results {
		byAddr[net.JoinHostPort(r.IP, fmt.Sprint(r.Port))] = r
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	var mu sync.Mutex
	for i := range rep.Findings {
		f := &rep.Findings[i]
		r := byAddr[net.JoinHostPort(f.Host, fmt.Sprint(f.Port))]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if progress != nil {
				mu.Lock()
				progress(tr(lang, "progress", f.Port, f.Service.Name))
				mu.Unlock()
			}
			a.verify(f, r, rep.Vantage, lang, p, blocked[f.Host])
		}()
	}
	wg.Wait()

	// A host found mute that answered a follow-up probe was only slow.
	for _, h := range muteHosts(results) {
		for _, f := range rep.Findings {
			if f.Host == h.host && answeredLate(f, lang) {
				rep.Alerts = remove(rep.Alerts, tr(lang, "alert-mute", h.host, h.tested))
				break
			}
		}
	}

	rep.ToFix, rep.ToReview, rep.Fine = 0, 0, 0
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
	sortFindings(rep.Findings)
	rep.Summary = tr(lang, "summary", rep.ToFix, rep.ToReview, rep.Fine)

	return DeepReport{
		Report:  rep,
		Profile: a.profile(rep, results, lang),
		Good:    a.goodNews(rep, results),
		Plan:    a.plan(rep),
	}
}

// blocked says the host blocked the scanner during the scan: what service
// detection missed was cut off, not slow.
func (a *Analyzer) verify(f *Finding, r scan.TargetResult, vantage, lang string, p Prober, blocked bool) {
	s := a.Dict.Get(f.Service.ID)
	proto := ""
	if s != nil {
		proto = s.Protocol()
	} else if strings.Contains(strings.ToLower(f.Service.Name), "ssh") {
		proto = "ssh"
	}
	host, port := f.Host, f.Port
	authVerified := false // a check showed the service refuses anonymous clients
	// noAnswer says a follow-up probe got nothing back: an unverified
	// hypothesis must not read like a verified one.
	noAnswer := func(protocol string) {
		f.Checks = append(f.Checks, Check{Kind: CheckNote, Text: tr(lang, "chk-no-answer", protocol, protocol)})
	}
	// answered settles a port service detection found silent: a follow-up
	// probe got an answer in protocol, so the service is there, only slow.
	answered := func(protocol string) {
		silent := tr(lang, "ev-silent")
		if !contains(f.Evidence, silent) {
			return
		}
		portOnly := tr(lang, "ev-port", f.Port, f.Service.Name)
		var kept []string
		for _, e := range f.Evidence {
			// Speaking SSH proves SSH; answering HTTPS does not prove which
			// web service it is.
			if e == silent || e == portOnly && protocol == "SSH" {
				continue
			}
			kept = append(kept, e)
		}
		why := "ev-answered-late"
		if blocked {
			why = "ev-answered-after-block"
		}
		f.Evidence = append(kept, tr(lang, why, protocol))
		if protocol == "SSH" && f.Service.Source == "port" {
			f.Service.Source, f.Service.Confidence = "probe", 0.99
		}
		if len(f.Service.Alternatives) == 0 && !contains(f.Evidence, tr(lang, "ev-cluster-node")) {
			f.Title = strings.TrimSuffix(f.Title, tr(lang, "to-confirm"))
		}
	}
	add := func(c Check) {
		f.Checks = append(f.Checks, c)
		if c.Kind != CheckIssue {
			return
		}
		if kb.SeverityRank(c.Severity) > kb.SeverityRank(f.Severity) {
			f.Severity = c.Severity
		}
		switch {
		case c.Severity == "critical" || c.Severity == "high":
			f.Verdict = Fix
		case f.Verdict == OK && kb.SeverityRank(c.Severity) >= kb.SeverityRank("low"):
			f.Verdict = Review
		}
	}

	switch {
	case proto == "ssh":
		openssh := strings.Contains(r.Banner, "OpenSSH")
		if methods, err := p.SSHAuthMethods(host, port); err == nil {
			answered("SSH")
			switch {
			case contains(methods, "none"):
				add(Check{Kind: CheckIssue, Severity: "critical", Text: tr(lang, "chk-ssh-none"), Fix: tr(lang, "fix-ssh-none")})
			case contains(methods, "password") || contains(methods, "keyboard-interactive"):
				sev := "medium"
				if vantage == Internal {
					sev = "low"
				}
				fix := tr(lang, "fix-ssh-password-openssh")
				switch {
				case f.Service.ID == "wings-sftp":
					// Wings checks SFTP logins against the panel: players log
					// in with their panel password by design. Turning
					// passwords off would lock them out of their files.
					sev, fix = "low", tr(lang, "fix-ssh-password-wings")
				case !openssh:
					fix = tr(lang, "fix-ssh-password-other")
				}
				add(Check{Kind: CheckIssue, Severity: sev, Text: tr(lang, "chk-ssh-password", strings.Join(methods, ", ")), Fix: fix})
			default:
				add(Check{Kind: CheckOK, Text: tr(lang, "chk-ssh-keys")})
			}
		} else {
			noAnswer("SSH")
		}
		if kex, macs, ciphers := weakSSH(r); len(kex)+len(macs)+len(ciphers) > 0 {
			fix, lines := sshWeakFix(lang, openssh, kex, macs, ciphers)
			add(Check{Kind: CheckIssue, Severity: "low",
				Text: tr(lang, "chk-ssh-weak", capList(lang, append(append(kex, macs...), ciphers...), 4)),
				Fix:  fix, Lines: lines})
		}

	case f.Service.ID == "kubelet":
		if code, _, _, err := p.HTTPGet(host, port, true, "/pods"); err == nil {
			answered("HTTPS")
			switch code {
			case http.StatusUnauthorized:
				add(Check{Kind: CheckOK, Text: tr(lang, "chk-kubelet-401")})
				authVerified = true
			case http.StatusForbidden:
				add(Check{Kind: CheckNote, Text: tr(lang, "chk-kubelet-403")})
			case http.StatusOK:
				add(Check{Kind: CheckIssue, Severity: "critical", Text: tr(lang, "chk-kubelet-200"), Fix: tr(lang, "fix-kubelet")})
			}
		} else {
			noAnswer("HTTPS")
		}

	case f.Service.ID == "kube-apiserver":
		if code, _, _, err := p.HTTPGet(host, port, true, "/api"); err == nil {
			answered("HTTPS")
			switch code {
			case http.StatusUnauthorized:
				add(Check{Kind: CheckOK, Text: tr(lang, "chk-api-401")})
				authVerified = true
			case http.StatusForbidden:
				add(Check{Kind: CheckNote, Text: tr(lang, "chk-api-403")})
			case http.StatusOK:
				add(Check{Kind: CheckIssue, Severity: "medium", Text: tr(lang, "chk-api-200"), Fix: tr(lang, "fix-api-anonymous")})
			}
		} else {
			noAnswer("HTTPS")
		}

	case f.Service.ID == "docker-api":
		code, _, body, err := p.HTTPGet(host, port, false, "/version")
		if err == nil {
			answered("HTTP")
		}
		switch {
		case err != nil:
			noAnswer("HTTP")
		case code == http.StatusOK && strings.Contains(body, "ApiVersion"):
			add(Check{Kind: CheckIssue, Severity: "critical", Text: tr(lang, "chk-docker-open"), Fix: f.Fix})
		}

	case f.Service.ID == "elasticsearch":
		if code, _, body, err := p.HTTPGet(host, port, false, "/"); err == nil {
			answered("HTTP")
			switch {
			case code == http.StatusOK && strings.Contains(body, "cluster_name"):
				add(Check{Kind: CheckIssue, Severity: "critical", Text: tr(lang, "chk-es-open"), Fix: f.Fix})
			case code == http.StatusUnauthorized:
				add(Check{Kind: CheckOK, Text: tr(lang, "chk-auth-required")})
				authVerified = true
			}
		} else {
			noAnswer("HTTP")
		}

	case f.Service.ID == "redis":
		switch b := strings.TrimSpace(r.Banner); {
		case strings.HasPrefix(b, "-NOAUTH") || strings.HasPrefix(b, "-DENIED"):
			add(Check{Kind: CheckOK, Text: tr(lang, "chk-auth-required")})
			authVerified = true
		case strings.HasPrefix(b, "$"):
			add(Check{Kind: CheckIssue, Severity: "critical", Text: tr(lang, "chk-redis-open"), Fix: f.Fix})
		}

	case proto == "http" && (f.Service.ID == "http-alt" || f.Service.ID == "pterodactyl-wings" || containsName(f.Service.Alternatives, "Pterodactyl Wings")):
		a.confirmWings(f, r, vantage, lang, p, add)

	case proto == "http" && port == 80:
		if code, hdr, _, err := p.HTTPGet(host, port, false, "/"); err == nil {
			answered("HTTP")
			loc := hdr.Get("Location")
			switch {
			case code >= 300 && code < 400 && strings.HasPrefix(strings.ToLower(loc), "https://"):
				add(Check{Kind: CheckOK, Text: tr(lang, "chk-http-redirect")})
			case code == http.StatusNotFound && net.ParseIP(host) != nil:
				add(Check{Kind: CheckNote, Text: tr(lang, "chk-http-ip-404")})
			case code == http.StatusOK:
				add(Check{Kind: CheckIssue, Severity: "low", Text: tr(lang, "chk-http-plain"), Fix: tr(lang, "fix-http-redirect")})
			}
		} else {
			noAnswer("HTTP")
		}

	case proto == "https" && port == 443 && r.TLS == nil:
		// Nothing was measured on this HTTPS port: does it answer at all?
		if _, _, _, err := p.HTTPGet(host, port, true, "/"); err != nil {
			noAnswer("HTTPS")
		} else {
			answered("HTTPS")
		}
	}

	// Inside the network, "check that it requires a login" was the open
	// question: once answered, the finding is settled.
	if authVerified && vantage == Internal && f.Verdict == Review && !hasIssue(f.Checks) {
		f.Verdict, f.Severity = OK, "info"
		f.Title = tr(lang, "title-internal-verified", f.Service.Name)
		f.Why, f.Fix = "", ""
	}

	// TLS, whatever the service: what the scan already measured.
	if t := r.TLS; t != nil {
		subject := strings.ToUpper(t.CertSubject)
		selfSigned := false
		for _, w := range t.Warnings {
			if strings.Contains(w, "self-signed") {
				selfSigned = true
			}
		}
		switch {
		case strings.Contains(subject, "TRAEFIK DEFAULT CERT"):
			add(Check{Kind: CheckNote, Text: tr(lang, "chk-tls-traefik-default")})
		case selfSigned && proto == "https":
			add(Check{Kind: CheckIssue, Severity: "medium", Text: tr(lang, "chk-tls-self-signed"), Fix: tr(lang, "fix-tls-cert")})
		}
		if t.CertDaysLeft > 0 && t.CertDaysLeft < 21 {
			add(Check{Kind: CheckIssue, Severity: "medium", Text: tr(lang, "chk-tls-expiry", t.CertDaysLeft), Fix: tr(lang, "fix-tls-renew")})
		}
		if t.Version == "TLS 1.3" && t.PQCReady {
			add(Check{Kind: CheckOK, Text: tr(lang, "chk-tls-modern")})
		}
		if t.Weak {
			add(Check{Kind: CheckIssue, Severity: "medium", Text: tr(lang, "chk-tls-weak"), Fix: tr(lang, "fix-tls-weak")})
		}
	}
}

// confirmWings tells Pterodactyl's Wings daemon (its own error text) from
// any other web service on an alternate port.
func (a *Analyzer) confirmWings(f *Finding, r scan.TargetResult, vantage, lang string, p Prober, add func(Check)) {
	for i, useTLS := range []bool{true, false} {
		code, _, body, err := p.HTTPGet(f.Host, f.Port, useTLS, "/api/system")
		if err != nil {
			if i == 1 {
				f.Checks = append(f.Checks, Check{Kind: CheckNote, Text: tr(lang, "chk-no-answer", "HTTP", "HTTP")})
			}
			continue
		}
		if code == http.StatusUnauthorized && strings.Contains(body, "authorization heads were not present") {
			r.Service = "wings"
			nf := a.judge(r, Options{Lang: lang, Vantage: vantage})
			nf.Service.Source = "probe"
			nf.Service.Alternatives = nil
			nf.Evidence = append(nf.Evidence, tr(lang, "ev-wings"))
			nf.Checks = f.Checks
			*f = nf
			add(Check{Kind: CheckOK, Text: tr(lang, "chk-wings-auth")})
		}
		return
	}
}

// weakSSH reads the weak algorithms out of the SSH posture warnings.
func weakSSH(r scan.TargetResult) (kex, macs, ciphers []string) {
	if r.SSHPosture == nil {
		return
	}
	for _, w := range r.SSHPosture.Warnings {
		i := strings.Index(w, ": ")
		if i < 0 {
			continue
		}
		var names []string
		for _, n := range strings.Split(w[i+2:], ",") {
			if n = strings.TrimSpace(n); n != "" && !strings.HasPrefix(n, "(+") {
				names = append(names, n)
			}
		}
		switch {
		case strings.HasPrefix(w, "weak key exchange"):
			kex = append(kex, names...)
		case strings.HasPrefix(w, "weak MAC"):
			macs = append(macs, names...)
		case strings.HasPrefix(w, "weak cipher"):
			ciphers = append(ciphers, names...)
		}
	}
	return
}

// sshWeakFix says how to stop offering weak algorithms, and for OpenSSH
// the sshd_config lines that do it.
func sshWeakFix(lang string, openssh bool, kex, macs, ciphers []string) (string, []string) {
	if !openssh {
		return tr(lang, "fix-ssh-weak-go"), nil
	}
	var lines []string
	if len(kex) > 0 {
		lines = append(lines, "KexAlgorithms -"+strings.Join(kex, ","))
	}
	if len(macs) > 0 {
		lines = append(lines, "MACs -"+strings.Join(macs, ","))
	}
	if len(ciphers) > 0 {
		lines = append(lines, "Ciphers -"+strings.Join(ciphers, ","))
	}
	return tr(lang, "fix-ssh-weak-openssh"), lines
}

// profile works out what the machine is from everything that answered.
func (a *Analyzer) profile(rep Report, results []scan.TargetResult, lang string) []string {
	hosts := map[string]bool{}
	for _, f := range rep.Findings {
		hosts[f.Host] = true
	}
	var out []string
	for host := range hosts {
		var roles, stack []string
		ids := map[string]bool{}
		var banners, certs []string
		for _, f := range rep.Findings {
			if f.Host == host {
				ids[f.Service.ID] = true
			}
		}
		for _, r := range results {
			if r.IP != host || !isOpen(r.State) {
				continue
			}
			banners = append(banners, r.Banner)
			if r.TLS != nil {
				certs = append(certs, strings.ToUpper(r.TLS.CertSubject+" "+r.TLS.CertIssuer))
			}
		}
		all := strings.Join(banners, " ")
		certAll := strings.Join(certs, " ")
		// roles name the machine ("a mail server"); traits describe it
		// ("running Minecraft servers") and need a role before them.
		var traits []string
		if ids["wings-sftp"] || ids["pterodactyl-wings"] {
			roles = append(roles, tr(lang, "prof-pterodactyl"))
		}
		if ids["smtp"] || ids["postfix"] || ids["exim"] {
			roles = append(roles, tr(lang, "prof-mail"))
		}
		if ids["minecraft"] {
			traits = append(traits, tr(lang, "prof-minecraft"))
		}
		if ids["https"] || ids["http"] || ids["nginx"] || ids["apache"] || ids["caddy"] {
			traits = append(traits, tr(lang, "prof-web"))
		}
		switch {
		case ids["kube-apiserver"] || ids["kubelet"] || strings.Contains(certAll, "K3S"):
			if strings.Contains(certAll, "K3S") {
				stack = append(stack, tr(lang, "prof-k3s"))
			} else {
				stack = append(stack, tr(lang, "prof-k8s"))
			}
		}
		if strings.Contains(certAll, "TRAEFIK") {
			stack = append(stack, tr(lang, "prof-traefik"))
		}
		switch {
		case strings.Contains(all, "deb13"):
			stack = append(stack, tr(lang, "prof-os", "Debian 13"))
		case strings.Contains(all, "deb12"):
			stack = append(stack, tr(lang, "prof-os", "Debian 12"))
		case strings.Contains(all, "Debian"):
			stack = append(stack, tr(lang, "prof-os", "Debian"))
		case strings.Contains(all, "Ubuntu"):
			stack = append(stack, tr(lang, "prof-os", "Ubuntu"))
		}
		machine := false
		switch {
		case len(roles) == 0 && len(traits) > 0:
			roles, machine = []string{tr(lang, "prof-machine")}, true
		case len(roles) == 0 && len(ids) == 1:
			roles = []string{tr(lang, "prof-generic-one")}
		case len(roles) == 0:
			roles = []string{tr(lang, "prof-generic", len(ids))}
		}
		sentence := strings.Join(roles, ", ")
		for i, t := range traits {
			if i == 0 && machine {
				sentence += " " + t // "a machine serving websites", no comma
			} else {
				sentence += ", " + t
			}
		}
		if len(stack) > 0 {
			sentence += ", " + strings.Join(stack, ", ")
		}
		out = append(out, host+tr(lang, "colon")+sentence+".")
	}
	sort.Strings(out)
	return out
}

// goodNews is what the analysis verified to be fine: worth saying, so the
// list of problems is read in proportion.
func (a *Analyzer) goodNews(rep Report, results []scan.TargetResult) []string {
	lang := rep.Lang
	var good []string
	// Where no port answered at all, closed ports are not good news.
	blind := map[string]bool{}
	for _, h := range blindHosts(results) {
		blind[h.host] = true
	}
	var seen []scan.TargetResult
	for _, r := range results {
		if !blind[r.IP] {
			seen = append(seen, r)
		}
	}
	results = seen
	if rep.Vantage == Internet {
		// An open port is judged by what was identified on it (2222 is SSH
		// here, not EtherNet/IP); a closed one by what its number is for.
		identified := map[string]*kb.Service{}
		for _, f := range rep.Findings {
			identified[net.JoinHostPort(f.Host, fmt.Sprint(f.Port))] = a.Dict.Get(f.Service.ID)
		}
		tested, open := 0, 0
		for _, r := range results {
			if isOpen(r.State) {
				if s := identified[net.JoinHostPort(r.IP, fmt.Sprint(r.Port))]; s != nil && s.Exposure == kb.Private {
					tested++
					open++
				}
				continue
			}
			cands := a.Dict.ByPort(r.Port)
			private := len(cands) > 0
			for _, s := range cands {
				if s.Exposure != kb.Private {
					private = false
				}
			}
			if private {
				tested++
			}
		}
		if tested > 0 && open == 0 {
			if tested == 1 {
				good = append(good, tr(lang, "good-private-closed-one"))
			} else {
				good = append(good, tr(lang, "good-private-closed", tested))
			}
		}
	}
	for _, f := range rep.Findings {
		for _, c := range f.Checks {
			if c.Kind == CheckOK {
				good = append(good, fmt.Sprintf("%d (%s) : %s", f.Port, f.Service.Name, c.Text))
			}
		}
	}
	return good
}

// plan orders what to do: verified issues and verdicts first by severity,
// then the cross-port observations.
func (a *Analyzer) plan(rep Report) []Action {
	lang := rep.Lang
	var plan []Action
	for _, f := range rep.Findings {
		where := net.JoinHostPort(f.Host, fmt.Sprint(f.Port))
		issues := 0
		for _, c := range f.Checks {
			if c.Kind == CheckIssue {
				issues++
				fix := c.Fix
				if len(c.Lines) > 0 || len([]rune(fix)) > 300 {
					// A long fix (a list of sshd_config lines) is in the port's
					// detail; the plan stays readable.
					fix = tr(lang, "plan-see-below")
				}
				plan = append(plan, Action{Severity: c.Severity, Where: where, Text: c.Text + " → " + fix})
			}
		}
		if f.Verdict != OK && f.Fix != "" && (issues == 0 || f.Verdict == Fix) {
			plan = append(plan, Action{Severity: f.Severity, Where: where, Text: f.Title + " → " + firstSentence(f.Fix)})
		}
	}
	// Several SSH entry points facing the internet: each is a door to defend.
	if rep.Vantage == Internet {
		byHost := map[string][]string{}
		for _, f := range rep.Findings {
			if s := a.Dict.Get(f.Service.ID); s != nil && s.Protocol() == "ssh" {
				byHost[f.Host] = append(byHost[f.Host], fmt.Sprint(f.Port))
			}
		}
		for host, ports := range byHost {
			if len(ports) >= 2 {
				plan = append(plan, Action{Severity: "low", Where: host + " : " + strings.Join(ports, ", "), Text: tr(lang, "plan-many-ssh", len(ports))})
			}
		}
	}
	sort.SliceStable(plan, func(i, j int) bool { return kb.SeverityRank(plan[i].Severity) > kb.SeverityRank(plan[j].Severity) })
	return plan
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		fi, fj := fs[i], fs[j]
		if vi, vj := verdictRank(fi.Verdict), verdictRank(fj.Verdict); vi != vj {
			return vi > vj
		}
		if si, sj := kb.SeverityRank(fi.Severity), kb.SeverityRank(fj.Severity); si != sj {
			return si > sj
		}
		if fi.Host != fj.Host {
			return fi.Host < fj.Host
		}
		return fi.Port < fj.Port
	})
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsName(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i+1]
	}
	return s
}

// capList joins the first n items and says how many more there are.
func capList(lang string, items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + " " + tr(lang, "more-items", len(items)-n)
}

// answeredLate reports a finding whose silent service answered a follow-up
// probe.
func answeredLate(f Finding, lang string) bool {
	for _, p := range []string{"SSH", "HTTP", "HTTPS"} {
		if contains(f.Evidence, tr(lang, "ev-answered-late", p)) || contains(f.Evidence, tr(lang, "ev-answered-after-block", p)) {
			return true
		}
	}
	return false
}

func remove(list []string, s string) []string {
	var out []string
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

func hasIssue(cs []Check) bool {
	for _, c := range cs {
		if c.Kind == CheckIssue {
			return true
		}
	}
	return false
}
