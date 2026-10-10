package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/compare"
	"github.com/NycolazSec/tcpcat/internal/explain"
	"github.com/NycolazSec/tcpcat/internal/inventory"
	"github.com/NycolazSec/tcpcat/internal/scan"
)

const explainUsage = `Explain who is behind each reachable port of a Linux host, and how to fix it.

  1. On the host, as root:      tcpcat inventory
                                (writes inventory.json; sends nothing on the network)
  2. Copy inventory.json to ANOTHER machine (your laptop), then run there:
                                tcpcat explain inventory.json --expect 22,80,443

  explain finds the host's public address in the inventory, probes the ports
  that matter from where it runs, and sorts every port into EXPOSED (who
  listens, how to fix), FORWARDED (NAT/Docker/Kubernetes), SHIELDED (only the
  firewall protects it), REFUSED, LOCAL.

  --expect <ports>   ports meant to be public, e.g. 22,80,443,25565-25570
  --target <ip>      address to probe (needed when the host has several public
                     addresses, or sits behind NAT)
  --ports <ports>    extra ports to probe
  -j <file>          also write the result as JSON

  Exit status: 0 nothing unexpected is reachable, 1 something is, 2 error.
  Advanced: tcpcat explain inventory.json scan.json uses a scan you ran yourself.
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
	if err := inv.Write(*out); err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	renderInventory(inv, *out)
	return exitOK
}

func runExplain(args []string) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	targetIP := fs.String("target", "", "Scanned address that is this host (needed behind NAT)")
	expectList := fs.String("expect", "", "Comma-separated ports meant to be public (e.g. 80,443)")
	jsonOut := fs.String("j", "", "Write the explanation as JSON")
	extraPorts := fs.String("ports", "", "Extra ports to probe besides the ones the inventory lists (e.g. 3306,8000-8010)")
	verbose := fs.Bool("v", false, "Also detail expected and local-only ports")
	fs.Usage = func() { fmt.Print(explainUsage) }

	var positional, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && a != "-v" && i+1 < len(args) {
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
	if len(positional) < 1 || len(positional) > 2 {
		fmt.Print(explainUsage)
		return exitError
	}

	expected := map[int]bool{}
	if *expectList != "" {
		ports, err := explain.ParsePortList(*expectList)
		if err != nil {
			fmt.Printf("%s[!] --expect: %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
		for _, p := range ports {
			expected[p] = true
		}
	}
	var extra []int
	if *extraPorts != "" {
		ports, err := explain.ParsePortList(*extraPorts)
		if err != nil {
			fmt.Printf("%s[!] --ports: %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
		extra = ports
	}

	inv, err := inventory.Load(positional[0])
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}

	var results []scan.TargetResult
	var target string
	var probe probeSummary
	if len(positional) == 2 {
		probe.fromFile = positional[1]
		// Advanced form: a scan report produced separately.
		if results, err = compare.LoadBaseline(positional[1]); err != nil {
			fmt.Printf("%s[!] scan report %s: %v%s\n", config.Red, positional[1], err, config.Reset)
			return exitError
		}
		if target, err = explain.SelectTarget(inv, results, *targetIP); err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
	} else {
		if target, results, probe, err = scanFromHere(inv, *targetIP, extra, expected); err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
	}

	rep := explain.Explain(inv, results, target, expected)
	renderExplain(rep, inv, probe, *verbose)

	if *jsonOut != "" {
		data, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*jsonOut, append(data, '\n'), 0600); err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
		fmt.Printf("  %sJSON report written to %s%s\n", config.Gray, *jsonOut, config.Reset)
	}
	if rep.Problems() > 0 {
		return exitViolation
	}
	return exitOK
}

// scanFromHere probes the host described by inv from this machine and
// returns the address used, the results and a summary for the header. It
// refuses to run on the host itself: connections to one's own address go
// through the loopback path and skip most firewall rules, so everything
// would look reachable.
func scanFromHere(inv inventory.Inventory, given string, extra []int, expected map[int]bool) (string, []scan.TargetResult, probeSummary, error) {
	var sum probeSummary
	target := given
	if target == "" {
		public := explain.PublicAddresses(inv)
		if len(public) == 0 {
			return "", nil, sum, fmt.Errorf("%s has no public address in its inventory (behind NAT?): pass the address to probe with --target", inv.Hostname)
		}
		target = public[0]
		if len(public) > 1 {
			fmt.Printf("  %s%s also has %s; probing %s (--target to pick another).%s\n",
				config.Gray, inv.Hostname, strings.Join(public[1:], ", "), target, config.Reset)
		}
	}
	if net.ParseIP(target) == nil {
		return "", nil, sum, fmt.Errorf("--target %q is not an IP address", target)
	}
	if isLocalAddress(target) {
		return "", nil, sum, fmt.Errorf("this machine owns %s: run explain from ANOTHER machine (your laptop), so the probes cross the firewall like real visitors", target)
	}

	var expectedList []int
	for p := range expected {
		expectedList = append(expectedList, p)
	}
	ports := explain.PortsToProbe(inv, append(extra, expectedList...))

	// A few slow, retried connect probes: the goal is a result that doesn't
	// flicker between runs, not speed (the port list is short).
	opts := auditScanOptions(20, 3)
	opts.MaxWorkers = 5
	opts.MaxRetries = 3
	opts.OnlyOpen = false // explain needs closed/filtered results too (SHIELDED, REFUSED)
	opts.Quiet = true
	engine := scan.NewEngine(opts)

	fmt.Printf("  %s●%s Probing %s%s%s on %d port(s) from this machine… ", config.Red, config.Reset, config.Bold+config.White, target, config.Reset, len(ports))
	results := engine.Execute([]string{target}, ports)
	for _, r := range results {
		if r.State == scan.StateOpen {
			sum.open++
		}
	}
	sum.probed = len(ports)
	fmt.Printf("%s%d open%s\n", config.White, sum.open, config.Reset)

	canaries := explain.CanaryPorts(inv, ports, 3)
	fmt.Printf("  %s●%s Checking the path with %d control port(s) where nothing listens… ", config.Red, config.Reset, len(canaries))
	var answered []string
	for _, r := range engine.Execute([]string{target}, canaries) {
		if r.State == scan.StateOpen {
			answered = append(answered, fmt.Sprint(r.Port))
		}
	}
	if len(answered) > 0 {
		fmt.Printf("%sFAILED%s\n", config.Bold+config.Red, config.Reset)
		cause := "a device between this machine and the host (VPN, phone hotspot, proxy, antivirus web shield, or anti-DDoS mitigation) answers on the host's behalf"
		if iface, addr := tunnelInterfaceFor(target); iface != "" {
			cause = fmt.Sprintf("traffic to %s leaves through tunnel interface %s (%s): a VPN is connected and its server answers on every port", target, iface, addr)
		}
		return "", nil, sum, fmt.Errorf("control port(s) %s answered although nothing listens there on %s: %s, so no result can be trusted. Disconnect the VPN (or exclude %s from it) and run explain again",
			strings.Join(answered, ", "), inv.Hostname, cause, target)
	}
	fmt.Printf("%sok%s\n", config.White, config.Reset)
	sum.pathCheck = true
	return target, results, sum, nil
}

func isLocalAddress(ip string) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.String() == ip {
			return true
		}
	}
	return false
}

// tunnelInterfaceFor reports the tunnel interface (utun/tun/wg/ppp/ipsec)
// the kernel would route target through, if any. Connecting a UDP socket
// only selects a route; nothing is sent.
func tunnelInterfaceFor(target string) (string, string) {
	conn, err := net.Dial("udp", net.JoinHostPort(target, "9")) // #nosec G704 -- route lookup only: connecting a UDP socket sends nothing, and target is the host the operator asked to probe
	if err != nil {
		return "", ""
	}
	local := conn.LocalAddr().(*net.UDPAddr).IP
	_ = conn.Close()
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(local) {
				for _, prefix := range []string{"utun", "tun", "wg", "ppp", "ipsec", "tap", "proton", "nordlynx"} {
					if strings.HasPrefix(ifc.Name, prefix) {
						return ifc.Name, local.String()
					}
				}
				return "", ""
			}
		}
	}
	return "", ""
}
