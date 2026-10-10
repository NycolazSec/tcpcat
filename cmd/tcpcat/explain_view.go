package main

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/explain"
	"github.com/NycolazSec/tcpcat/internal/inventory"
)

// Console rendering of `tcpcat explain`: a header, one section per verdict
// (problems first), local-only ports folded into one line, and a verdict.
// Palette per config: red = needs attention, white = primary, gray = detail.

const ruleWidth = 80

func rule() string { return config.Gray + strings.Repeat("─", ruleWidth) + config.Reset }

// probeSummary describes how the outside view was obtained, for the header.
type probeSummary struct {
	probed    int  // ports probed from this machine (0: scan report given)
	open      int  // of which answered open
	pathCheck bool // canary ports confirmed nothing answers on the host's behalf
	fromFile  string
}

type section struct {
	title, hint, color string
	entries            []explain.Entry
	// footer replaces a per-entry generic fix shared by the whole section.
	footer string
}

func renderExplain(rep explain.Report, inv inventory.Inventory, probe probeSummary, verbose bool) {
	fmt.Println(rule())
	kv := func(k, v string) { fmt.Printf("  %s%-8s%s %s\n", config.Gray, k, config.Reset, v) }
	kv("HOST", config.Bold+config.White+inv.Hostname+config.Reset+config.Gray+"  ·  "+rep.Target+config.Reset)
	kv("INSIDE", fmt.Sprintf("%d listening socket(s), inventory taken %s", len(inv.Listeners), inv.CollectedAt.Format("2006-01-02 15:04 UTC")))
	if probe.fromFile != "" {
		kv("OUTSIDE", "scan report "+probe.fromFile)
	} else {
		check := config.Red + "not run" + config.Reset
		if probe.pathCheck {
			check = "passed"
		}
		kv("OUTSIDE", fmt.Sprintf("%d port(s) probed from this machine, %d open  ·  path check %s", probe.probed, probe.open, check))
	}
	fmt.Println(rule())

	var fix, firewall, refused, untested, expected, local []explain.Entry
	for _, e := range rep.Entries {
		switch {
		case e.Expected && e.Class != explain.Local && e.Class != explain.Refused:
			expected = append(expected, e)
		case e.Class == explain.Exposed || e.Class == explain.Forwarded:
			fix = append(fix, e)
		case e.Class == explain.Shielded:
			firewall = append(firewall, e)
		case e.Class == explain.Refused:
			refused = append(refused, e)
		case e.Class == explain.Untested:
			untested = append(untested, e)
		default:
			local = append(local, e)
		}
	}

	sections := []section{
		{"TO FIX", "reachable from outside, not declared with --expect", config.Red, fix, ""},
		{"FIREWALL ONLY", "listening on every interface; one firewall rule keeps them off the network", config.White, firewall,
			"Defense in depth: bind the ones nothing remote needs to 127.0.0.1, so a firewall mistake can't expose them."},
		{"REFUSED", "listening, but connections are turned away", config.White, refused, ""},
		{"NOT PROBED", "listening on a reachable address; add them with --ports", config.White, untested,
			"Re-run with --ports to probe them."},
	}
	for _, s := range sections {
		if len(s.entries) == 0 {
			continue
		}
		fmt.Printf("\n  %s%s%s (%d)%s  %s%s%s\n", config.Bold, s.color, s.title, len(s.entries), config.Reset, config.Gray, s.hint, config.Reset)
		for _, e := range s.entries {
			// With a section footer, only a daemon-specific fix (it names
			// the knob in parentheses) is worth repeating per port.
			renderEntry(e, s.color, s.footer == "" || strings.Contains(e.Fix, "("))
		}
		if s.footer != "" {
			fmt.Printf("    %-21s %s→ %s%s\n", "", config.Gray, s.footer, config.Reset)
		}
	}

	if len(expected) > 0 {
		fmt.Printf("\n  %s%sPUBLIC AS EXPECTED (%d)%s\n", config.Bold, config.White, len(expected), config.Reset)
		for _, e := range expected {
			renderEntry(e, config.White, verbose)
		}
	}

	if len(local) > 0 {
		fmt.Printf("\n  %s%sLOCAL ONLY (%d)%s  ", config.Bold, config.White, len(local), config.Reset)
		if verbose {
			fmt.Printf("%sloopback or another address; not reachable%s\n", config.Gray, config.Reset)
			for _, e := range local {
				renderEntry(e, config.Gray, false)
			}
		} else {
			ports := make([]int, 0, len(local))
			for _, e := range local {
				ports = append(ports, e.Port)
			}
			fmt.Printf("%s%s%s  %s(-v for details)%s\n", config.White, compactPorts(ports), config.Reset, config.Gray, config.Reset)
		}
	}

	fmt.Println()
	fmt.Println(rule())
	n := rep.Problems()
	if n > 0 {
		fmt.Printf("  %s%s✗ %d port(s) reachable that should not be.%s  %sFix them, or declare the intended ones with --expect.%s\n",
			config.Bold, config.Red, n, config.Reset, config.Gray, config.Reset)
	} else {
		fmt.Printf("  %s%s✓ Nothing unexpected is reachable on %s.%s\n", config.Bold, config.White, rep.Target, config.Reset)
	}
	if len(firewall) > 0 {
		fmt.Printf("  %s%d port(s) rely on the firewall alone (defense in depth: also bind them to 127.0.0.1).%s\n", config.Gray, len(firewall), config.Reset)
	}
	fmt.Println(rule())
}

// renderEntry prints one port: a headline (port, verdict, owner, severity),
// a short reason, and -- when detailed -- the fix, wrapped.
func renderEntry(e explain.Entry, color string, detailed bool) {
	sev := ""
	switch e.Severity {
	case "high":
		sev = config.Bold + config.Red + "HIGH" + config.Reset
	case "medium":
		sev = config.Red + "MEDIUM" + config.Reset
	case "low":
		sev = config.Gray + "LOW" + config.Reset
	}
	if e.Expected {
		sev = ""
	}
	owner := shortOwner(e)
	fmt.Printf("    %s%-10s%s %s%-10s%s %-44s %s\n",
		config.Bold+color, fmt.Sprintf("%d/tcp", e.Port), config.Reset,
		config.Gray, e.Class, config.Reset,
		truncate(owner, 44), sev)
	fmt.Printf("    %s%-21s %s%s\n", config.Gray, "", shortWhy(e), config.Reset)
	if detailed && e.Fix != "" && (!e.Expected || e.Class == explain.Refused) {
		for i, line := range wrap(e.Fix, ruleWidth-28) {
			arrow := " "
			if i == 0 {
				arrow = "→"
			}
			fmt.Printf("    %-21s %s%s %s%s\n", "", config.White, arrow, line, config.Reset)
		}
	}
}

// shortOwner: "mariadbd · mariadb.service", "docker-proxy · container mock-aws",
// "→ kube-system/traefik (LoadBalancer)".
func shortOwner(e explain.Entry) string {
	if e.Kube != nil {
		return "→ " + e.Kube.Name + " (" + e.Kube.Type + ")"
	}
	o := e.Owner
	if o == nil {
		if e.Class == explain.Forwarded {
			return "→ forwarded (no local listener)"
		}
		return "unidentified process"
	}
	s := o.Process
	switch {
	case o.ContainerName != "":
		s += " · container " + shortID(o.ContainerName)
	case o.Pod != "":
		s += " · pod " + o.Pod
	case o.Container != "":
		s += " · container " + shortID(o.Container)
	case o.Unit != "":
		s += " · " + o.Unit
	}
	return s
}

// shortWhy is the one-line reason shown under each port; the full sentence
// stays in the JSON report.
func shortWhy(e explain.Entry) string {
	bound := strings.Join(e.Listeners, ", ")
	switch e.Class {
	case explain.Exposed:
		return "reachable from outside · listens on " + bound
	case explain.Forwarded:
		if e.Kube != nil {
			why := "reachable · Kubernetes redirects it into the cluster"
			if e.Owner != nil && len(e.Listeners) > 0 {
				why += " (" + e.Owner.Process + " also listens locally, gets none of it)"
			}
			return why
		}
		return "reachable, but nothing on the host listens for it: NAT / port forwarding"
	case explain.Shielded:
		return "listens on " + bound + " · blocked from outside"
	case explain.Refused:
		if e.Owner != nil && e.Owner.Process == "docker-proxy" {
			return "Docker publishes it, but nothing listens on " + e.Owner.ForwardsTo + " in the container"
		}
		return "listens on " + bound + " · connections refused"
	case explain.Untested:
		return "listens on " + bound + " · not probed"
	}
	return "listens on " + bound + " only"
}

// shortID shortens 64-hex container IDs and Pterodactyl-style UUID names.
func shortID(s string) string {
	if len(s) >= 32 && strings.Trim(strings.ToLower(s), "0123456789abcdef-") == "" {
		return s[:8] + "…"
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, w := range strings.Fields(text) {
		if line != "" && len([]rune(line))+1+len([]rune(w)) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// compactPorts: [25 53 10256 10257 10258] -> "25, 53, 10256-10258".
func compactPorts(ports []int) string {
	sort.Ints(ports)
	var parts []string
	for i := 0; i < len(ports); {
		j := i
		for j+1 < len(ports) && ports[j+1] == ports[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", ports[i], ports[j]))
		} else {
			parts = append(parts, strconv.Itoa(ports[i]))
		}
		i = j + 1
	}
	return strings.Join(parts, ", ")
}

// renderInventory prints the inside view grouped by exposure surface.
func renderInventory(inv inventory.Inventory, out string) {
	var wide, local []inventory.Listener
	for _, l := range inv.Listeners {
		if ip := net.ParseIP(l.Address); ip != nil && ip.IsLoopback() {
			local = append(local, l)
		} else {
			wide = append(wide, l)
		}
	}
	fmt.Println(rule())
	fmt.Printf("  %sHOST%s     %s%s%s  ·  %d listening socket(s)\n", config.Gray, config.Reset, config.Bold+config.White, inv.Hostname, config.Reset, len(inv.Listeners))
	fmt.Println(rule())
	print := func(title, hint string, list []inventory.Listener) {
		if len(list) == 0 {
			return
		}
		fmt.Printf("\n  %s%s%s (%d)%s  %s%s%s\n", config.Bold, config.White, title, len(list), config.Reset, config.Gray, hint, config.Reset)
		for _, l := range list {
			fmt.Printf("    %s%-10s%s %-24s %s\n", config.Bold+config.White, fmt.Sprintf("%d/tcp", l.Port), config.Reset,
				truncate(l.Address, 24), truncate(shortOwner(explain.Entry{Owner: l.Owner}), 44))
		}
	}
	print("NETWORK-FACING", "bound to every interface or a non-loopback address", wide)
	print("LOOPBACK ONLY", "not reachable from the network", local)
	if len(inv.Services) > 0 {
		fmt.Printf("\n  %s%sKUBERNETES SERVICES (%d)%s  %sNodePort / LoadBalancer%s\n", config.Bold, config.White, len(inv.Services), config.Reset, config.Gray, config.Reset)
		for _, s := range inv.Services {
			np := ""
			if s.NodePort > 0 {
				np = fmt.Sprintf(" (node port %d)", s.NodePort)
			}
			fmt.Printf("    %s%-10s%s %s%s\n", config.Bold+config.White, fmt.Sprintf("%d/tcp", s.Port), config.Reset, s.Name+" · "+s.Type, np)
		}
	}
	fmt.Println()
	fmt.Println(rule())
	fmt.Printf("  %s✓ Written to %s%s\n", config.White, out, config.Reset)
	fmt.Printf("  %sNext: copy %s to another machine (your laptop) and run there:%s\n", config.Gray, out, config.Reset)
	fmt.Printf("    %stcpcat explain %s --expect 22,80,443%s\n", config.Bold+config.White, out, config.Reset)
	fmt.Println(rule())
}
