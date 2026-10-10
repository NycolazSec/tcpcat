package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/policy"
	"github.com/NycolazSec/tcpcat/internal/scan"
	"github.com/NycolazSec/tcpcat/internal/target"
)

// Exit codes shared by the audit subcommands: 0 = compliant / nothing
// reproduced, 1 = violation found, 2 = usage or runtime error. Distinct
// codes let a CI step fail on a finding without hiding a broken setup.
const (
	exitOK        = 0
	exitViolation = 1
	exitError     = 2
)

const policyUsage = `Usage:
  tcpcat policy check <policy.yaml> --from <vantage> [-j report.json] [--sarif report.sarif]
                      [--rate <pps>] [-T <0-5>] [--scope-file <file>]
  tcpcat policy matrix <report.json>...

check   Scans, from where tcpcat runs now (--from names that vantage), every
        rule of the policy whose "from" matches, using TCP connect probes
        (no root needed). Exit status: 0 compliant, 1 violation, 2 error.
matrix  Merges reports from several vantages into one from/to table.
`

func runPolicy(args []string) int {
	if len(args) == 0 {
		fmt.Print(policyUsage)
		return exitError
	}
	switch args[0] {
	case "check":
		return runPolicyCheck(args[1:])
	case "matrix":
		return runPolicyMatrix(args[1:])
	case "-h", "--help", "help":
		fmt.Print(policyUsage)
		return exitOK
	default:
		fmt.Printf("%s[!] Unknown policy command %q.%s\n\n%s", config.Red, args[0], config.Reset, policyUsage)
		return exitError
	}
}

func runPolicyCheck(args []string) int {
	fs := flag.NewFlagSet("policy check", flag.ContinueOnError)
	from := fs.String("from", "", "Vantage this run is executed from (matches the rules' `from`)")
	jsonOut := fs.String("j", "", "Write the JSON report to this file")
	sarifOut := fs.String("sarif", "", "Write violations as SARIF 2.1.0")
	rate := fs.Int("rate", 300, "Max connection attempts per second")
	timing := fs.Int("T", 3, "Timing template (0-5)")
	scopeFile := fs.String("scope-file", "", "Refuse to probe anything outside this authorized scope")
	fs.Usage = func() { fmt.Print(policyUsage) }

	file, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil {
		return exitError
	}
	if file == "" || *from == "" {
		fmt.Printf("%s[!] policy check needs a policy file and --from.%s\n\n%s", config.Red, config.Reset, policyUsage)
		return exitError
	}
	if *timing < 0 || *timing > 5 {
		fmt.Printf("%s[!] -T must be between 0 and 5.%s\n", config.Red, config.Reset)
		return exitError
	}

	pol, err := policy.Load(file)
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	resolve := func(entries []string) ([]string, error) {
		ips, _, err := target.ParseTargetsWithNames(entries)
		if err != nil {
			return nil, err
		}
		if *scopeFile != "" {
			inScope, err := target.FilterByScope(ips, *scopeFile)
			if err != nil {
				return nil, err
			}
			if len(inScope) != len(ips) {
				return nil, fmt.Errorf("%d address(es) are outside %s", len(ips)-len(inScope), *scopeFile)
			}
		}
		return ips, nil
	}
	checks, err := pol.Plan(*from, resolve)
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	if len(checks) == 0 {
		fmt.Printf("%s[!] No rule applies from %q. Vantages in this policy: %s%s\n",
			config.Red, *from, strings.Join(pol.Vantages(), ", "), config.Reset)
		return exitError
	}

	name := pol.Name
	if name == "" {
		name = file
	}
	fmt.Printf("%s[*] Policy %q from vantage %q: %d rule(s) to check.%s\n", config.Bold, name, *from, len(checks), config.Reset)

	report := policy.Report{Policy: name, Vantage: *from, CheckedAt: time.Now().UTC()}
	for _, check := range checks {
		fmt.Println(config.Bold + "────────────────────────────────────────────────────────────────────────────────" + config.Reset)
		fmt.Printf("%s[*] Rule %q: %s -> %s (%d host(s) x %d port(s))%s\n",
			config.White, check.Rule.Name, check.Rule.From, check.Rule.To, len(check.Targets), len(check.Ports), config.Reset)

		results := scan.NewEngine(auditScanOptions(*rate, *timing)).Execute(check.Targets, check.Ports)
		var open []policy.Endpoint
		for _, r := range results {
			if r.State == scan.StateOpen {
				open = append(open, policy.Endpoint{IP: r.IP, Port: r.Port})
			}
		}
		res := policy.NewCheckResult(check, open)
		report.Checks = append(report.Checks, res)

		if res.Status == policy.StatusPass {
			fmt.Printf("%s[✓] PASS: %d reachable port(s), all allowed.%s\n", config.White, len(res.Open), config.Reset)
			continue
		}
		for _, v := range res.Violations {
			if v.Kind == policy.ViolationRequiredClosed {
				fmt.Printf("%s[✗] FAIL: %s:%d must be reachable from %s but is not.%s\n", config.Red, v.IP, v.Port, check.Rule.From, config.Reset)
			} else {
				fmt.Printf("%s[✗] FAIL: %s:%d is reachable from %s and not allowed.%s\n", config.Red, v.IP, v.Port, check.Rule.From, config.Reset)
			}
		}
	}
	report.Finalize()

	fmt.Println(config.Bold + "────────────────────────────────────────────────────────────────────────────────" + config.Reset)
	policy.PrintMatrix(os.Stdout, []policy.Report{report})

	if *jsonOut != "" {
		if err := report.WriteJSON(*jsonOut); err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
		fmt.Printf("%s[✓] Report written to %s%s\n", config.White, *jsonOut, config.Reset)
	}
	if *sarifOut != "" {
		if err := report.WriteSARIF(*sarifOut); err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
		fmt.Printf("%s[✓] SARIF written to %s%s\n", config.White, *sarifOut, config.Reset)
	}
	if report.Status == policy.StatusFail {
		fmt.Printf("%s[✗] Segmentation policy violated from %q.%s\n", config.Red, *from, config.Reset)
		return exitViolation
	}
	fmt.Printf("%s[✓] Segmentation policy respected from %q.%s\n", config.White, *from, config.Reset)
	return exitOK
}

func runPolicyMatrix(paths []string) int {
	if len(paths) == 0 {
		fmt.Print(policyUsage)
		return exitError
	}
	var reports []policy.Report
	failed := false
	for _, path := range paths {
		r, err := policy.LoadReport(path)
		if err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
		if r.Status == policy.StatusFail {
			failed = true
		}
		reports = append(reports, r)
	}
	policy.PrintMatrix(os.Stdout, reports)
	if failed {
		return exitViolation
	}
	return exitOK
}

// auditScanOptions are the scan settings the audit subcommands share: a
// kernel TCP connect scan (no root, no raw packets, nothing spoofed),
// paced at rate, printing only open ports.
func auditScanOptions(rate, timing int) *config.Options {
	return &config.Options{
		ConnectScan:    true,
		Timing:         timing,
		RateLimit:      rate,
		MaxRetries:     1,
		MaxWorkers:     256,
		BatchSize:      1000,
		ConnPoolSize:   64,
		OnlyOpen:       true,
		EvasionMode:    "off",
		TTLMode:        "fixed",
		SourcePortMode: "fixed",
		ProbeTTL:       64,
	}
}

// splitPositional pulls the first non-flag argument out of args so it can
// appear before or after the flags (flag.Parse stops at the first one).
func splitPositional(args []string) (string, []string) {
	var positional string
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && flagTakesValue(a) {
				rest = append(rest, args[i+1])
				i++
			}
			continue
		}
		if positional == "" {
			positional = a
		} else {
			rest = append(rest, a)
		}
	}
	return positional, rest
}

// flagTakesValue lists the audit subcommands' value flags (all others are
// booleans), so splitPositional doesn't swallow a file name after a bool.
func flagTakesValue(flagName string) bool {
	switch strings.TrimLeft(flagName, "-") {
	case "from", "j", "sarif", "rate", "T", "scope-file", "out", "key", "pub", "o", "finding":
		return true
	}
	return false
}
