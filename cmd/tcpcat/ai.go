package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/ai"
	"github.com/NycolazSec/tcpcat/internal/ai/kb"
	"github.com/NycolazSec/tcpcat/internal/ai/model"
	"github.com/NycolazSec/tcpcat/internal/compare"
	"github.com/NycolazSec/tcpcat/internal/scan"
)

const aiUsage = `tcpcat's AI: reads a scan and tells you, in plain words, what is exposed,
how serious it is, why, and what to do. It runs offline, inside tcpcat.

  tcpcat ai explain <scan.json>     judge every open port of a scan (-j scan.json)
  tcpcat ai explain --deep <scan>   take the time: verify each hypothesis with read-only
                                    follow-up probes, profile the machine, plan the fixes
  tcpcat ai policy <scan.json>      draft the exposure policy for tcpcat policy check
  tcpcat ai identify "<banner>"     name the service behind a banner
  tcpcat ai model                   what the AI knows and how it was trained

  Or add --ai (quick) or --ai-deep (thorough) to a scan: tcpcat -sV --ai-deep <target>

  --lang <code>       language of the answers: en, fr or a translation (default: from $LANG)
  --from internet|internal
                      where the scan ran from (default: internal when every
                      scanned address is private, internet otherwise)
  -j <file>           (explain) also write the findings as JSON
  --policy <file>     (explain) also write the draft policy
  -o <file>           (policy) where to write it (default: exposure.yaml)
  --port <n>          (identify) port the banner came from

  explain exits 1 when something should be fixed, 0 otherwise, 2 on error.
`

const aiUsageFR = `L'IA de tcpcat : elle lit un scan et vous dit, avec des mots simples, ce qui
est exposé, à quel point c'est grave, pourquoi, et quoi faire. Elle tourne hors
ligne, dans tcpcat.

  tcpcat ai explain <scan.json>     juge chaque port ouvert d'un scan (-j scan.json)
  tcpcat ai explain --deep <scan>   prend son temps : vérifie chaque hypothèse par
                                    des sondes en lecture seule, dresse le profil de
                                    la machine, planifie les corrections
  tcpcat ai policy <scan.json>      rédige la politique d'exposition pour tcpcat policy check
  tcpcat ai identify "<bannière>"   nomme le service derrière une bannière
  tcpcat ai model                   ce que l'IA sait et comment elle a été entraînée

  Ou ajoutez --ai (rapide) ou --ai-deep (approfondi) à un scan :
  tcpcat -sV --ai-deep <cible>

  --lang <code>       langue des réponses : en, fr ou une traduction (par défaut : selon $LANG)
  --from internet|internal
                      d'où le scan a été lancé (par défaut : internal quand toutes les
                      adresses scannées sont privées, internet sinon)
  -j <fichier>        (explain) écrit aussi les constats en JSON
  --policy <fichier>  (explain) écrit aussi le brouillon de politique
  -o <fichier>        (policy) où l'écrire (par défaut : exposure.yaml)
  --port <n>          (identify) port d'où vient la bannière

  explain se termine avec le code 1 s'il y a quelque chose à corriger, 0 sinon,
  2 en cas d'erreur.
`

// usageIn is the help of tcpcat ai in a language.
func usageIn(lang string) string { return msg(lang, aiUsage, aiUsageFR) }

func runAI(args []string) int {
	l := defaultLang()
	if len(args) == 0 {
		fmt.Print(usageIn(l))
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
		return runAIModel(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usageIn(l))
		return exitOK
	default:
		fmt.Printf("%s[!] %s %q.%s\n\n%s", config.Red, msg(l, "Unknown ai command", "Commande ai inconnue"), args[0], config.Reset, usageIn(l))
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
	fs.Usage = func() { fmt.Print(usageIn(defaultLang())) }
	f := aiFlags{fs: fs}
	f.lang = fs.String("lang", defaultLang(), "Language of the answers: "+strings.Join(ai.Languages(), ", "))
	f.from = fs.String("from", "", "Where the scan ran from: internet or internal")
	return f
}

func defaultLang() string {
	for _, v := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if l := os.Getenv(v); l != "" {
			return ai.Lang(l)
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
	a, results, opt, code := loadScan(f, args)
	if code != exitOK {
		return nil, ai.Report{}, code
	}
	return a, a.Analyze(results, opt), exitOK
}

func loadScan(f aiFlags, args []string) (*ai.Analyzer, []scan.TargetResult, ai.Options, int) {
	file, rest := splitPositional(args)
	if err := f.fs.Parse(rest); err != nil {
		return nil, nil, ai.Options{}, exitError
	}
	if file == "" {
		fmt.Printf("%s[!] %s%s\n\n%s", config.Red, msg(*f.lang, "Give the JSON report of a scan (tcpcat -sV -j scan.json <target>).",
			"Donnez le rapport JSON d'un scan (tcpcat -sV -j scan.json <cible>)."), config.Reset, usageIn(*f.lang))
		return nil, nil, ai.Options{}, exitError
	}
	if *f.from != "" && *f.from != ai.Internet && *f.from != ai.Internal {
		fmt.Printf("%s[!] %s%s\n", config.Red, msg(*f.lang, "--from must be internet or internal.", "--from doit valoir internet ou internal."), config.Reset)
		return nil, nil, ai.Options{}, exitError
	}
	results, err := compare.LoadBaseline(file)
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return nil, nil, ai.Options{}, exitError
	}
	a, err := ai.New()
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return nil, nil, ai.Options{}, exitError
	}
	return a, results, ai.Options{Lang: *f.lang, Vantage: vantageFor(results, *f.from)}, exitOK
}

func runAIExplain(args []string) int {
	f := newAIFlags("explain")
	f.jsonOut = f.fs.String("j", "", "Also write the findings as JSON")
	f.polOut = f.fs.String("policy", "", "Also write the draft exposure policy")
	deep := f.fs.Bool("deep", false, "Verify each hypothesis with read-only follow-up probes (contacts the scanned hosts)")
	a, results, opt, code := loadScan(f, args)
	if code != exitOK {
		return code
	}
	var rep ai.Report
	var out any
	if *deep {
		d := runDeep(a, results, opt)
		rep, out = d.Report, d
	} else {
		rep = a.Analyze(results, opt)
		out = rep
		renderAIReport(rep)
	}
	if *f.jsonOut != "" {
		data, _ := json.MarshalIndent(out, "", "  ")
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
		fmt.Printf("%s[!] %s%s\n", config.Red, msg(rep.Lang, "A draft exposure policy needs a scan run from the internet (--from internet).",
			"Un brouillon de politique d'exposition demande un scan lancé depuis Internet (--from internet)."), config.Reset)
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
	fs.Usage = func() { fmt.Print(usageIn(defaultLang())) }
	port := fs.Int("port", 0, "Port the banner came from")
	lang := fs.String("lang", defaultLang(), "Language of the answers: "+strings.Join(ai.Languages(), ", "))
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
		fmt.Printf("%s[!] %s%s\n", config.Red, msg(*lang, "Give a banner, a --port, or both.", "Donnez une bannière, un --port, ou les deux."), config.Reset)
		return exitError
	}
	a, err := ai.New()
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	r := scan.TargetResult{Port: *port, Banner: banner, State: "OPEN"}
	id := a.Identify(r, *lang)
	name := func(id string) string {
		if s := a.Dict.Get(id); s != nil {
			return s.DisplayName(*lang)
		}
		return id
	}
	pct := func(p float64) string { return fmt.Sprintf(ai.PercentFormat(*lang), fmt.Sprintf("%3.0f", 100*p)) }
	fmt.Printf("%s%s%s\n", config.Bold, msg(*lang, "Most likely:", "Le plus probable :"), config.Reset)
	var families []model.Guess
	if banner != "" {
		guesses := a.Model.Classify(banner, *port)
		for i, g := range guesses {
			if i == 3 || g.P < 0.01 {
				break
			}
			fmt.Printf("  %s%s%s  %s\n", config.White, pct(g.P), config.Reset, name(g.ID))
		}
		// Unsure of the product: say how sure it is of the kind of service.
		if families = a.Families(guesses); guesses[0].P < 0.5 && len(families) > 0 {
			fmt.Printf("%s%s%s\n", config.Bold, msg(*lang, "By kind of service:", "Par type de service :"), config.Reset)
			for i, f := range families {
				if i == 3 || f.P < 0.01 {
					break
				}
				fmt.Printf("  %s%s%s  %s\n", config.White, pct(f.P), config.Reset, name(f.ID))
			}
		}
	}
	s := a.Dict.Get(id.ID)
	if s == nil {
		switch {
		case len(families) >= 2:
			fmt.Println()
			printItem("  ", msg(*lang,
				fmt.Sprintf("Not sure enough to decide: %s or %s? The banner does not say clearly.", name(families[0].ID), name(families[1].ID)),
				fmt.Sprintf("Pas assez sûre pour trancher : %s ou %s ? La bannière ne le dit pas clairement.", name(families[0].ID), name(families[1].ID))))
		default:
			fmt.Printf("  %s\n", msg(*lang, "The dictionary does not know this service.", "Le dictionnaire ne connaît pas ce service."))
		}
		return exitOK
	}
	fmt.Printf("\n%s%s%s  %s\n", config.Bold, s.DisplayName(*lang), config.Reset, s.What.In(*lang))
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

func runAIModel(args []string) int {
	fs := flag.NewFlagSet("ai model", flag.ContinueOnError)
	fs.Usage = func() { fmt.Print(usageIn(defaultLang())) }
	lang := fs.String("lang", defaultLang(), "Language of the answers: "+strings.Join(ai.Languages(), ", "))
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	l := *lang
	a, err := ai.New()
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	m, st := a.Model, a.Model.Stats
	label := func(en, fr string) string { return fmt.Sprintf("%s%-13s%s", config.Bold, msg(l, en, fr), config.Reset) }
	pad := strings.Repeat(" ", 13)
	fmt.Printf("%s %s\n", label("Dictionary", "Dictionnaire"), fmt.Sprintf(msg(l, "%s services, %s known ports", "%s services, %s ports connus"),
		number(l, len(a.Dict.All())), number(l, len(a.Dict.Ports()))))
	fmt.Printf("%s %s\n", label("Model", "Modèle"), msg(l,
		"logistic regression over the banner (n-grams, words, first characters, shape), plus the port",
		"régression logistique sur la bannière (n-grammes, mots, premiers caractères, forme), plus le port"))
	fmt.Printf("%s %s\n", pad, fmt.Sprintf(msg(l, "%d classes, %s weights, port weight %s, temperature %s", "%d classes, %s poids, poids du port %s, température %s"),
		len(m.Classes), number(l, m.Size()), decimal(l, m.PortWeight), decimal(l, m.Temperature)))
	if st.Date != "" {
		printItem(label("Trained", "Entraînée")+" ", fmt.Sprintf(msg(l,
			"%s, from %s banners: %s, %s of them generated from its patterns; %s examples under %d network conditions",
			"le %s, à partir de %s bannières : %s, dont %s générées à partir de ses motifs ; %s exemples sous %d conditions réseau"),
			st.Date, number(l, st.Banners), st.Source, number(l, st.Generated), number(l, st.Examples), len(model.Conditions)))
	}
	if len(st.Scores) > 0 {
		fmt.Printf("\n%s%s%s\n", config.Bold, msg(l, "On banners it never saw:", "Sur des bannières qu'elle n'a jamais vues :"), config.Reset)
		fmt.Printf("  %-34s %9s %9s %9s\n", "", msg(l, "service", "service"), msg(l, "product", "produit"), msg(l, "ports", "ports"))
		for _, sc := range st.Scores {
			name := sc.Condition
			exact := percent(l, sc.Exact)
			for _, c := range model.Conditions {
				if c.Name == sc.Condition {
					name = msg(l, c.Label[0], c.Label[1])
					if c.ProtocolOnly {
						exact = "-"
					}
				}
			}
			fmt.Printf("  %-34s %9s %9s %9s\n", name, percent(l, sc.Protocol), exact, percent(l, sc.Detector))
		}
		printItem(config.Gray+"  ", msg(l,
			"service: the right kind of service; product: the right software; ports: tcpcat's signatures and port conventions alone",
			"service : le bon type de service ; produit : le bon logiciel ; ports : les signatures et les ports habituels de tcpcat seuls")+config.Reset)
	}
	fmt.Printf("\n%s %s\n", label("Evaluation", "Évaluation"), "internal/ai/model/EVALUATION.md")
	return exitOK
}

// number writes an integer with the language's thousands separator.
func number(lang string, n int) string {
	s := strconv.Itoa(n)
	sep := ai.ThousandsSeparator(lang)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteString(sep)
		}
		b.WriteRune(c)
	}
	return b.String()
}

// decimal writes a number with two decimals and the language's decimal mark.
func decimal(lang string, f float32) string {
	return strings.Replace(strconv.FormatFloat(float64(f), 'f', 2, 32), ".", ai.DecimalMark(lang), 1)
}

// percent writes a share as a percentage with one decimal.
func percent(lang string, f float32) string {
	s := strings.Replace(strconv.FormatFloat(float64(100*f), 'f', 1, 32), ".", ai.DecimalMark(lang), 1)
	return fmt.Sprintf(ai.PercentFormat(lang), s)
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
	if len(rep.Story) > 0 || len(rep.Alerts) > 0 {
		fmt.Printf("\n  %s%s%s\n", config.Bold, msg(l, "How the scan went", "Comment le scan s'est déroulé"), config.Reset)
		printStory(rep)
	}
	renderFindings(rep, false)
}

// printStory says first what the scan cannot tell (the alerts), then how
// it went.
func printStory(rep ai.Report) {
	for _, a := range rep.Alerts {
		printItem("  "+config.Yellow+"!"+config.Reset+" ", a)
	}
	for _, s := range rep.Story {
		printItem("  "+config.Gray+"·"+config.Reset+" ", s)
	}
}

func renderFindings(rep ai.Report, withChecks bool) {
	l := rep.Lang
	// After the quick report's alerts, a one-line entry needs a blank line
	// before it (a detailed one starts with its own).
	if !withChecks && len(rep.Alerts) > 0 && (len(rep.Findings) == 0 || rep.Findings[0].Verdict == ai.OK) {
		fmt.Println()
	}
	if len(rep.Findings) == 0 {
		fmt.Printf("  %s\n", msg(l, "No open port in this scan.", "Aucun port ouvert dans ce scan."))
		return
	}
	for _, f := range rep.Findings {
		color := severityColor(f.Severity)
		addr := net.JoinHostPort(f.Host, fmt.Sprint(f.Port))
		if f.Verdict == ai.OK {
			fmt.Printf("  %s[ok]%s %-22s %s\n", config.Green, config.Reset, addr, f.Title)
			if withChecks {
				printChecks(l, f.Checks)
			}
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
		if withChecks {
			printChecks(l, f.Checks)
		}
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
	switch s {
	case "critical":
		return msg(lang, "critical", "critique")
	case "high":
		return msg(lang, "high", "élevé")
	case "medium":
		return msg(lang, "medium", "moyen")
	case "low":
		return msg(lang, "low", "faible")
	case "info":
		return msg(lang, "info", "info")
	}
	return s
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

// msg writes a phrase of the command line in lang: French, a locale's
// translation (keyed by the English text), or English.
func msg(lang, en, fr string) string {
	if lang == "fr" {
		return fr
	}
	if s := ai.Phrase(lang, en); s != "" {
		return s
	}
	return en
}

// printAIAfterScan is the --ai flag: the same analysis, on the results the
// scan just produced.
func printAIAfterScan(results []scan.TargetResult, lang, from string, deep bool) {
	if lang == "" {
		lang = defaultLang()
	}
	if deep {
		a, err := ai.New()
		if err != nil {
			fmt.Printf("%s[!] AI: %v%s\n", config.Red, err, config.Reset)
			return
		}
		runDeep(a, results, ai.Options{Lang: lang, Vantage: vantageFor(results, from), FromClusterNode: onClusterNode(), BehindNAT: behindNAT(results)})
		return
	}
	sp := startSpinner(lang, thinkingVerbs)
	a, err := ai.New()
	if err != nil {
		sp.Stop()
		fmt.Printf("%s[!] AI: %v%s\n", config.Red, err, config.Reset)
		return
	}
	rep := a.Analyze(results, ai.Options{Lang: lang, Vantage: vantageFor(results, from), FromClusterNode: onClusterNode(), BehindNAT: behindNAT(results)})
	sp.Stop()
	renderAIReport(rep)
}

// behindNAT reports whether this scan reached its targets through a router
// that translates addresses, such as a home box (see ai.Options.BehindNAT).
func behindNAT(results []scan.TargetResult) bool {
	seen := map[string]bool{}
	var ips []string
	for _, r := range results {
		if !seen[r.IP] {
			seen[r.IP] = true
			ips = append(ips, r.IP)
		}
	}
	_, ok := scan.SourceBehindNAT(ips)
	return ok
}

// clusterNodePaths exist on a Kubernetes node (k3s, kubeadm, kubelet).
var clusterNodePaths = []string{"/etc/rancher/k3s", "/var/lib/rancher/k3s", "/var/lib/kubelet", "/etc/kubernetes/kubelet.conf"}

// onClusterNode reports whether tcpcat runs on a Kubernetes node: the
// cluster's firewall may then let this machine reach ports the internet
// cannot.
func onClusterNode() bool {
	for _, p := range clusterNodePaths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// runDeep runs the thorough analysis, showing what it checks, and prints it.
func runDeep(a *ai.Analyzer, results []scan.TargetResult, opt ai.Options) ai.DeepReport {
	l := ai.Lang(opt.Lang)
	fmt.Printf("\n%s%s%s\n", config.Bold, msg(l, "tcpcat AI: thorough analysis", "IA de tcpcat : analyse approfondie"), config.Reset)
	sp := startSpinner(l, verifyingVerbs)
	d := a.Deep(results, opt, ai.NetProber{Timeout: 5 * time.Second}, sp.Step)
	sp.Stop()
	renderDeepReport(d)
	return d
}

// renderDeepReport: what the machine is, what is fine, the plan, then the
// detail of every port with what was verified.
func renderDeepReport(d ai.DeepReport) {
	l := d.Lang
	section := func(en, fr string) { fmt.Printf("\n%s%s%s\n", config.Bold+config.Red, msg(l, en, fr), config.Reset) }
	if len(d.Story) > 0 || len(d.Alerts) > 0 {
		section("How the scan went", "Comment le scan s'est déroulé")
		printStory(d.Report)
	}
	if len(d.Profile) > 0 {
		section("What I understood", "Ce que j'ai compris")
		for _, p := range d.Profile {
			printItem("  ", p)
		}
	}
	if len(d.Good) > 0 {
		section("What is fine", "Ce qui va bien")
		for _, g := range d.Good {
			printItem("  "+config.Green+"✓"+config.Reset+" ", g)
		}
	}
	if len(d.Plan) > 0 {
		section("What I would do, in order", "Ce que je ferais, dans l'ordre")
		for i, act := range d.Plan {
			tag := fmt.Sprintf("%s[%s]%s", severityColor(act.Severity), strings.ToUpper(severityLabel(l, act.Severity)), config.Reset)
			printItem(fmt.Sprintf("  %d. %s ", i+1, tag), act.Where+"  "+act.Text)
		}
	}
	section("Port by port", "Port par port")
	renderFindings(d.Report, true)
}

// printItem prints text after prefix, wrapped at 92 columns with a hanging
// indent under the text.
func printItem(prefix, text string) {
	visible := len([]rune(stripANSI(prefix)))
	pad := strings.Repeat(" ", visible)
	line, n := prefix, visible
	// Only plain spaces break a line: a no-break space holds "9 878" together.
	for _, w := range strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' }) {
		k := len([]rune(w))
		if n > visible && n+1+k > 92 {
			fmt.Println(line)
			line, n = pad, visible
		}
		if n > visible {
			line += " "
			n++
		}
		line += w
		n += k
	}
	fmt.Println(line)
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

// printChecks lists what a deep analysis verified on a finding.
func printChecks(l string, checks []ai.Check) {
	for _, c := range checks {
		mark := config.Green + "✓" + config.Reset
		switch c.Kind {
		case ai.CheckIssue:
			mark = config.Red + "✗" + config.Reset
		case ai.CheckNote:
			mark = config.Yellow + "•" + config.Reset
		}
		printItem("     "+config.Gray+fmt.Sprintf("%-8s", msg(l, "check", "contrôle"))+config.Reset+" "+mark+" ", c.Text)
		if c.Kind == ai.CheckIssue && c.Fix != "" {
			// What to do about it, under it: the plan refers here for the
			// long fixes (exact sshd_config lines).
			printItem("                "+config.Gray+"→"+config.Reset+" ", c.Fix)
			// Configuration lines are printed as they are, to be copied.
			for _, line := range c.Lines {
				fmt.Printf("                  %s\n", line)
			}
		}
	}
}
