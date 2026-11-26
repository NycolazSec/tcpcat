package ai

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/NycolazSec/tcpcat/internal/ai/kb"
)

// DraftPolicy writes an exposure policy (the YAML that `tcpcat policy check`
// reads) from what an internet-vantage analysis found: for each host, the
// expected public services are allowed and required, restricted ones are
// allowed with a comment, and everything else, including every port the
// dictionary marks private, must stay closed. It is a draft: the comments
// say what to look at before adopting it.
func (a *Analyzer) DraftPolicy(rep Report, name string) []byte {
	lang := rep.Lang
	hosts := map[string][]Finding{}
	var order []string
	for _, f := range rep.Findings {
		if _, ok := hosts[f.Host]; !ok {
			order = append(order, f.Host)
		}
		hosts[f.Host] = append(hosts[f.Host], f)
	}
	sort.Strings(order)

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n", tr(lang, "pol-head"))
	fmt.Fprintf(&b, "# %s\n", tr(lang, "pol-check"))
	b.WriteString("version: 1\n")
	fmt.Fprintf(&b, "name: %s\n", quote(name))
	b.WriteString("zones:\n")
	for i, h := range order {
		fmt.Fprintf(&b, "  host%d: [%s]\n", i+1, quote(h))
	}
	b.WriteString("rules:\n")
	for i, h := range order {
		var allow, require []int
		var closeNotes, reviewNotes []string
		probe := map[int]bool{}
		for _, p := range a.Dict.Ports() {
			if s := a.privateOn(p); s {
				probe[p] = true
			}
		}
		for _, f := range hosts[h] {
			probe[f.Port] = true
			label := fmt.Sprintf("%d %s", f.Port, f.Service.Name)
			switch {
			case f.Exposure == kb.Public && f.Verdict != Fix:
				allow = append(allow, f.Port)
				require = append(require, f.Port)
			case f.Exposure == kb.Public || f.Exposure == kb.Restricted:
				allow = append(allow, f.Port)
				reviewNotes = append(reviewNotes, label)
			default:
				closeNotes = append(closeNotes, label)
			}
		}
		sort.Ints(allow)
		sort.Ints(require)
		fmt.Fprintf(&b, "  - name: %s\n", quote(tr(lang, "pol-rule", h)))
		if len(closeNotes) > 0 {
			fmt.Fprintf(&b, "    # %s %s\n", tr(lang, "pol-close"), strings.Join(closeNotes, ", "))
		}
		if len(reviewNotes) > 0 {
			fmt.Fprintf(&b, "    # %s %s\n", tr(lang, "pol-review"), strings.Join(reviewNotes, ", "))
		}
		b.WriteString("    from: internet\n")
		fmt.Fprintf(&b, "    to: host%d\n", i+1)
		fmt.Fprintf(&b, "    ports: %s\n", quote(portList(probe)))
		fmt.Fprintf(&b, "    allow: [%s]\n", tcpList(allow))
		if len(require) > 0 {
			fmt.Fprintf(&b, "    require: [%s]\n", joinInts(require))
		}
	}
	return []byte(b.String())
}

// privateOn reports whether a port belongs only to services that must not
// face the internet, so the draft keeps checking it stays closed.
func (a *Analyzer) privateOn(port int) bool {
	cands := a.Dict.ByPort(port)
	if len(cands) == 0 {
		return false
	}
	for _, s := range cands {
		if s.Exposure != kb.Private {
			return false
		}
	}
	return true
}

func portList(set map[int]bool) string {
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return joinInts(ports)
}

func joinInts(ps []int) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}

func tcpList(ps []int) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = strconv.Itoa(p) + "/tcp"
	}
	return strings.Join(s, ", ")
}

func quote(s string) string { return strconv.Quote(s) }

func init() {
	for k, v := range map[string][2]string{
		"pol-head":   {"Draft written by tcpcat's AI from a scan. Read it before you adopt it.", "Brouillon écrit par l'IA de tcpcat à partir d'un scan. Relisez-le avant de l'adopter."},
		"pol-check":  {"Check it with: tcpcat policy check <this file> --from internet", "Vérification : tcpcat policy check <ce fichier> --from internet"},
		"pol-rule":   {"only the expected services of %s are public", "seuls les services prévus de %s sont publics"},
		"pol-close":  {"must be closed first:", "à fermer d'abord :"},
		"pol-review": {"allowed for now, limit them by source address:", "autorisés pour l'instant, limitez-les par adresse source :"},
	} {
		messages[k] = v
	}
}
