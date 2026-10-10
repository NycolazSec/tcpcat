package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/compare"
	"github.com/NycolazSec/tcpcat/internal/explain"
	"github.com/NycolazSec/tcpcat/internal/inventory"
)

const explainUsage = `Usage:
  tcpcat inventory [-o inventory.json]
      On the host (Linux, as root): list every listening TCP port with the
      process, systemd unit, container or pod that owns it. Sends nothing
      on the network.

  tcpcat explain <inventory.json> <scan.json> [--target <ip>] [--expect 80,443] [-j report.json]
      Join that inventory with a scan of the same host taken from OUTSIDE
      (tcpcat <host> -p 1-65535 -j scan.json, from another machine) and
      explain every port: EXPOSED (who listens, how to fix), FORWARDED
      (reachable with no local listener: NAT/Docker/Kubernetes), SHIELDED
      (only the firewall protects it), LOCAL, UNTESTED.
      --expect lists ports meant to be public. Exit status: 0 nothing
      unexpected is reachable, 1 something is, 2 error.
`

func runInventory(args []string) int {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	out := fs.String("o", "inventory.json", "Write the inventory to this file")
	fs.Usage = func() { fmt.Print(explainUsage) }
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	inv, err := inventory.Collect()
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	for _, w := range inv.Warnings {
		fmt.Printf("%s[!] %s%s\n", config.Red, w, config.Reset)
	}

	sort.Slice(inv.Listeners, func(i, j int) bool {
		if inv.Listeners[i].Port != inv.Listeners[j].Port {
			return inv.Listeners[i].Port < inv.Listeners[j].Port
		}
		return inv.Listeners[i].Address < inv.Listeners[j].Address
	})
	fmt.Printf("%s%-6s %-28s %s%s\n", config.Bold, "PORT", "BOUND TO", "OWNER", config.Reset)
	for _, l := range inv.Listeners {
		fmt.Printf("%-6d %-28s %s\n", l.Port, l.Address, ownerSummary(l.Owner))
	}
	if err := inv.Write(*out); err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	fmt.Printf("%s[✓] %d listening socket(s) on %s written to %s.%s\n", config.White, len(inv.Listeners), inv.Hostname, *out, config.Reset)
	fmt.Printf("%s[*] Next: scan this host from another machine (tcpcat <address> -sT -Pn -p 1-65535 -j scan.json), then: tcpcat explain %s scan.json%s\n",
		config.Gray, *out, config.Reset)
	return exitOK
}

func ownerSummary(o *inventory.Owner) string {
	if o == nil {
		return "?"
	}
	s := fmt.Sprintf("%s[%d]", o.Process, o.PID)
	switch {
	case o.ContainerName != "":
		s += " container=" + o.ContainerName
	case o.Pod != "":
		s += " pod=" + o.Pod
	case o.Container != "":
		s += " container=" + o.Container[:12]
	case o.Unit != "":
		s += " unit=" + o.Unit
	}
	if o.ForwardsTo != "" {
		s += " -> " + o.ForwardsTo
	}
	return s
}

func runExplain(args []string) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	targetIP := fs.String("target", "", "Scanned address that is this host (needed behind NAT)")
	expectList := fs.String("expect", "", "Comma-separated ports meant to be public (e.g. 80,443)")
	jsonOut := fs.String("j", "", "Write the explanation as JSON")
	fs.Usage = func() { fmt.Print(explainUsage) }

	var positional, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	if err := fs.Parse(flags); err != nil {
		return exitError
	}
	if len(positional) != 2 {
		fmt.Print(explainUsage)
		return exitError
	}

	expected := map[int]bool{}
	if *expectList != "" {
		for _, p := range strings.Split(*expectList, ",") {
			port, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(p), "/tcp")))
			if err != nil || port < 1 || port > 65535 {
				fmt.Printf("%s[!] --expect: invalid port %q%s\n", config.Red, p, config.Reset)
				return exitError
			}
			expected[port] = true
		}
	}

	inv, err := inventory.Load(positional[0])
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	results, err := compare.LoadBaseline(positional[1])
	if err != nil {
		fmt.Printf("%s[!] scan report %s: %v%s\n", config.Red, positional[1], err, config.Reset)
		return exitError
	}
	target, err := explain.SelectTarget(inv, results, *targetIP)
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}

	rep := explain.Explain(inv, results, target, expected)
	fmt.Printf("%s[*] Explaining %s (scanned as %s): %d port(s) seen from inside and/or outside.%s\n",
		config.Bold, inv.Hostname, target, len(rep.Entries), config.Reset)
	fmt.Println(config.Bold + "────────────────────────────────────────────────────────────────────────────────" + config.Reset)
	for _, e := range rep.Entries {
		color, mark := config.Gray, "[i]"
		switch {
		case (e.Class == explain.Exposed || e.Class == explain.Forwarded) && !e.Expected:
			color, mark = config.Red, "[!]"
			if e.Severity == "high" {
				mark = "[!!]"
			}
		case e.Class == explain.Shielded && e.Severity == "low":
			color, mark = config.White, "[~]"
		case e.Expected:
			color, mark = config.White, "[✓]"
		}
		label := e.Class
		if e.Expected {
			label += " (expected)"
		}
		svc := ""
		if e.Service != "" && e.Service != "unknown" {
			svc = " " + e.Service
		}
		fmt.Printf("%s%-4s %-20s %5d/tcp%s%s\n", color, mark, label, e.Port, svc, config.Reset)
		fmt.Printf("     %s%s%s\n", config.Gray, e.Why, config.Reset)
		if e.Fix != "" && (!e.Expected || e.Class != explain.Exposed) {
			fmt.Printf("     %sfix: %s%s\n", config.White, e.Fix, config.Reset)
		}
	}
	fmt.Println(config.Bold + "────────────────────────────────────────────────────────────────────────────────" + config.Reset)

	if *jsonOut != "" {
		data, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*jsonOut, append(data, '\n'), 0600); err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
		fmt.Printf("%s[✓] Explanation written to %s%s\n", config.White, *jsonOut, config.Reset)
	}
	if n := rep.Problems(); n > 0 {
		fmt.Printf("%s[✗] %d port(s) reachable without being declared with --expect.%s\n", config.Red, n, config.Reset)
		return exitViolation
	}
	fmt.Printf("%s[✓] Nothing unexpected is reachable on %s.%s\n", config.White, target, config.Reset)
	return exitOK
}
