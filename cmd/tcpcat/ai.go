package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/ai"
	"github.com/NycolazSec/tcpcat/internal/ai/kb"
	"github.com/NycolazSec/tcpcat/internal/compare"
	"github.com/NycolazSec/tcpcat/internal/scan"
)

const aiUsage = `tcpcat's AI: reads a scan and tells you, in plain words, what is exposed,
how serious it is, why, and what to do. It runs offline, inside tcpcat.

  tcpcat ai explain <scan.json>     judge every open port of a scan (-j scan.json)
  tcpcat ai policy <scan.json>      draft the exposure policy for tcpcat policy check
  tcpcat ai identify "<banner>"     name the service behind a banner
  tcpcat ai model                   what the AI knows and how it was trained

  Or add --ai to a scan: tcpcat -sV --ai <target>

  --lang fr|en        language of the answers (default: from $LANG)
  --from internet|internal
                      where the scan ran from (default: internal when every
                      scanned address is private, internet otherwise)
  -j <file>           (explain) also write the findings as JSON
  --policy <file>     (explain) also write the draft policy
  -o <file>           (policy) where to write it (default: exposure.yaml)
  --port <n>          (identify) port the banner came from

  explain exits 1 when something should be fixed, 0 otherwise, 2 on error.
`

func runAI(args []string) int {
	if len(args) == 0 {
		fmt.Print(aiUsage)
		return exitError
	}
	switch args[0] {
	case "explain":
		return runAIExplain(args[1:])
	case "policy":
		return runAIPolicy(args[1:])
	case "identify":
		return runAIIdentify(args[1:])
	case "model":
		return runAIModel()
	case "-h", "--help", "help":
		fmt.Print(aiUsage)
		return exitOK
	default:
		fmt.Printf("%s[!] Unknown ai command %q.%s\n\n%s", config.Red, args[0], config.Reset, aiUsage)
		return exitError
	}
}

// aiFlags are shared by explain and policy.
type aiFlags struct {
	fs                          *flag.FlagSet
	lang, from, jsonOut, polOut *string
}

func newAIFlags(name string) aiFlags {
	fs := flag.NewFlagSet("ai "+name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Print(aiUsage) }
	f := aiFlags{fs: fs}
	f.lang = fs.String("lang", defaultLang(), "Language of the answers: fr or en")
	f.from = fs.String("from", "", "Where the scan ran from: internet or internal")
	return f
}

func defaultLang() string {
	for _, v := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if l := os.Getenv(v); l != "" {
			if strings.HasPrefix(strings.ToLower(l), "fr") {
				return "fr"
			}
			return "en"
		}
	}
	return "en"
}

// vantageFor guesses where a scan ran from when the user did not say: a scan
// of private addresses only was run from inside the network.
func vantageFor(results []scan.TargetResult, given string) string {
	switch given {
	case ai.Internet, ai.Internal:
		return given
	}
	for _, r := range results {
		ip := net.ParseIP(r.IP)
		if ip == nil || !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return ai.Internet
		}
	}
	if len(results) == 0 {
		return ai.Internet
	}
	return ai.Internal
}

func loadAnalysis(f aiFlags, args []string) (*ai.Analyzer, ai.Report, int) {
	file, rest := splitPositional(args)
	if err := f.fs.Parse(rest); err != nil {
		return nil, ai.Report{}, exitError
	}
	if file == "" {
		fmt.Printf("%s[!] Give the JSON report of a scan (tcpcat -sV -j scan.json <target>).%s\n\n%s", config.Red, config.Reset, aiUsage)
		return nil, ai.Report{}, exitError
	}
	if *f.from != "" && *f.from != ai.Internet && *f.from != ai.Internal {
		fmt.Printf("%s[!] --from must be internet or internal.%s\n", config.Red, config.Reset)
		return nil, ai.Report{}, exitError
	}
	results, err := compare.LoadBaseline(file)
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return nil, ai.Report{}, exitError
	}
	a, err := ai.New()
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return nil, ai.Report{}, exitError
	}
	rep := a.Analyze(results, ai.Options{Lang: *f.lang, Vantage: vantageFor(results, *f.from)})
	return a, rep, exitOK
}

func runAIExplain(args []string) int {
	f := newAIFlags("explain")
	f.jsonOut = f.fs.String("j", "", "Also write the findings as JSON")
	f.polOut = f.fs.String("policy", "", "Also write the draft exposure policy")
	a, rep, code := loadAnalysis(f, args)
	if code != exitOK {
		return code
	}
	renderAIReport(rep)
	if *f.jsonOut != "" {
		data, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*f.jsonOut, data, 0o600); err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
	}
	if *f.polOut != "" {
		if code := writeDraftPolicy(a, rep, *f.polOut); code != exitOK {
			return code
		}
	}
	if rep.ToFix > 0 {
		return exitViolation
	}
	return exitOK
}

func runAIPolicy(args []string) int {
	f := newAIFlags("policy")
	f.polOut = f.fs.String("o", "exposure.yaml", "Where to write the draft policy")
	a, rep, code := loadAnalysis(f, args)
	if code != exitOK {
		return code
	}
	return writeDraftPolicy(a, rep, *f.polOut)
}

func writeDraftPolicy(a *ai.Analyzer, rep ai.Report, path string) int {
	if rep.Vantage != ai.Internet {
		fmt.Printf("%s[!] A draft exposure policy needs a scan run from the internet (--from internet).%s\n", config.Red, config.Reset)
		return exitError
	}
	data := a.DraftPolicy(rep, msg(rep.Lang, "public exposure", "exposition publique"))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	fmt.Printf("%s[✓] %s %s%s\n", config.Green, msg(rep.Lang, "Draft policy written to", "Brouillon de politique écrit dans"), path, config.Reset)
	return exitOK
}

func runAIIdentify(args []string) int {
	fs := flag.NewFlagSet("ai identify", flag.ContinueOnError)
	fs.Usage = func() { fmt.Print(aiUsage) }
	port := fs.Int("port", 0, "Port the banner came from")
	lang := fs.String("lang", defaultLang(), "Language of the answers: fr or en")
	// A banner may itself start with "-" (Redis answers "-NOAUTH ..."), so
	// the first argument is the banner unless it is one of this command's flags.
	var banner string
	rest := args
	if len(args) > 0 && !isIdentifyFlag(args[0]) {
		banner, rest = args[0], args[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return exitError
	}
	if banner == "" && *port == 0 {
		fmt.Printf("%s[!] Give a banner, a --port, or both.%s\n", config.Red, config.Reset)
		return exitError
	}
	a, err := ai.New()
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	r := scan.TargetResult{Port: *port, Banner: banner, State: "OPEN"}
	id := a.Identify(r, *lang)
	fmt.Printf("%s%s%s\n", config.Bold, msg(*lang, "Most likely:", "Le plus probable :"), config.Reset)
	if banner != "" {
		for i, g := range a.Model.Classify(banner, *port) {
			if i == 3 || g.P < 0.01 {
				break
			}
			name := g.ID
			if s := a.Dict.Get(g.ID); s != nil {
				name = s.Name
			}
			fmt.Printf("  %s%3.0f%%%s  %s\n", config.White, 100*g.P, config.Reset, name)
		}
	}
	s := a.Dict.Get(id.ID)
	if s == nil {
		fmt.Printf("  %s\n", msg(*lang, "The dictionary does not know this service.", "Le dictionnaire ne connaît pas ce service."))
		return exitOK
	}
	fmt.Printf("\n%s%s%s  %s\n", config.Bold, s.Name, config.Reset, s.What.In(*lang))
	fmt.Printf("  %s  %s\n", msg(*lang, "internet:", "Internet :"), exposureLabel(*lang, s.Exposure))
	if w := s.Why.In(*lang); w != "" {
		printWrapped(msg(*lang, "why", "pourquoi"), w)
	}
	if h := s.Hint.In(*lang); h != "" {
		printWrapped(msg(*lang, "advice", "conseil"), h)
	}
	return exitOK
}

func isIdentifyFlag(a string) bool {
	name := strings.SplitN(strings.TrimLeft(a, "-"), "=", 2)[0]
	return strings.HasPrefix(a, "-") && (name == "port" || name == "lang" || name == "h" || name == "help")
}

func runAIModel() int {
	a, err := ai.New()
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	fmt.Printf("%sDictionary%s  %d services, %d known ports\n", config.Bold, config.Reset, len(a.Dict.All()), len(a.Dict.Ports()))
	fmt.Printf("%sModel%s       naive Bayes over banner n-grams + port, %d classes, %d weights\n", config.Bold, config.Reset, len(a.Model.Classes), a.Model.Size())
	fmt.Printf("            temperature %.0f, port weight %.0f\n", a.Model.Temperature, a.Model.PortWeight)
	fmt.Printf("%sTrained%s     %s\n", config.Bold, config.Reset, a.Model.Trained)
	fmt.Printf("%sEvaluation%s  internal/ai/model/EVALUATION.md (accuracy under 7 network conditions)\n", config.Bold, config.Reset)
	return exitOK
}

// renderAIReport prints findings worst first: full detail for what needs
// action, one line for what is fine.
func renderAIReport(rep ai.Report) {
	l := rep.Lang
	title := msg(l, "tcpcat AI", "IA de tcpcat")
	vantage := map[string][2]string{
		ai.Internet: {"seen from the internet", "vu depuis Internet"},
		ai.Internal: {"seen from inside the network", "vu depuis le réseau interne"},
	}[rep.Vantage]
	fmt.Printf("\n%s%s%s %s(%s)%s\n", config.Bold, title, config.Reset, config.Gray, msg(l, vantage[0], vantage[1]), config.Reset)
	if len(rep.Findings) == 0 {
		fmt.Printf("  %s\n", msg(l, "No open port in this scan.", "Aucun port ouvert dans ce scan."))
		return
	}
	for _, f := range rep.Findings {
		color := severityColor(f.Severity)
		addr := net.JoinHostPort(f.Host, fmt.Sprint(f.Port))
		if f.Verdict == ai.OK {
			fmt.Printf("  %s[ok]%s %-22s %s\n", config.Green, config.Reset, addr, f.Title)
			continue
		}
		fmt.Printf("\n  %s[%s]%s %s  %s%s%s\n", color, strings.ToUpper(severityLabel(l, f.Severity)), config.Reset, addr, config.Bold, f.Title, config.Reset)
		if f.Why != "" {
			printWrapped(msg(l, "why", "pourquoi"), f.Why)
		}
		if f.Fix != "" {
			printWrapped(msg(l, "fix", "action"), f.Fix)
		}
		printWrapped(msg(l, "proof", "preuves"), strings.Join(f.Evidence, " · "))
	}
	color := config.Green
	if rep.ToFix > 0 {
		color = config.Red
	} else if rep.ToReview > 0 {
		color = config.Yellow
	}
	fmt.Printf("\n%s%s%s\n", color+config.Bold, rep.Summary, config.Reset)
}

func printWrapped(label, text string) {
	const width = 80
	prefix := fmt.Sprintf("     %s%-8s%s ", config.Gray, label, config.Reset)
	pad := strings.Repeat(" ", 14) // the visible width of prefix
	var line []string
	n, first := 0, true
	flush := func() {
		p := pad
		if first {
			p, first = prefix, false
		}
		fmt.Println(p + strings.Join(line, " "))
		line, n = nil, 0
	}
	for _, w := range strings.Fields(text) {
		if n > 0 && n+1+utf8.RuneCountInString(w) > width {
			flush()
		}
		if n > 0 {
			n++
		}
		line = append(line, w)
		n += utf8.RuneCountInString(w)
	}
	if len(line) > 0 || first {
		flush()
	}
}

func severityColor(s string) string {
	switch s {
	case "critical", "high":
		return config.Red
	case "medium":
		return config.Yellow
	}
	return config.White
}

func severityLabel(lang, s string) string {
	if lang != "fr" {
		return s
	}
	return map[string]string{"critical": "critique", "high": "élevé", "medium": "moyen", "low": "faible", "info": "info"}[s]
}

func exposureLabel(lang, e string) string {
	switch e {
	case kb.Public:
		return msg(lang, "meant to be public", "fait pour être public")
	case kb.Restricted:
		return msg(lang, "acceptable if limited to known addresses", "acceptable si limité à des adresses connues")
	}
	return msg(lang, "should never be reachable", "ne doit jamais être joignable")
}

func msg(lang, en, fr string) string {
	if lang == "fr" {
		return fr
	}
	return en
}

// printAIAfterScan is the --ai flag: the same analysis, on the results the
// scan just produced.
func printAIAfterScan(results []scan.TargetResult, lang, from string) {
	a, err := ai.New()
	if err != nil {
		fmt.Printf("%s[!] AI: %v%s\n", config.Red, err, config.Reset)
		return
	}
	if lang == "" {
		lang = defaultLang()
	}
	renderAIReport(a.Analyze(results, ai.Options{Lang: lang, Vantage: vantageFor(results, from)}))
}
