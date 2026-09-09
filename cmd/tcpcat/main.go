package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"tcpcat/config"
	"tcpcat/internal/compare"
	"tcpcat/internal/discovery"
	"tcpcat/internal/output"
	"tcpcat/internal/ports"
	"tcpcat/internal/scan"
	"tcpcat/internal/service"
	"tcpcat/internal/target"
	"tcpcat/internal/update"
	"tcpcat/internal/vuln"
	"tcpcat/internal/web"
)

func main() {
	opts, err := config.ParseFlags()
	if err != nil {
		fmt.Printf("%s[!] Configuration error: %v%s\n", config.Red, err, config.Reset)
		os.Exit(1)
	}
	config.ApplyProfile(opts)

	fmt.Println(config.Banner)
	if opts.Update {
		if err := update.Run(os.Args[0], "NycolazSec", "tcpcat"); err != nil {
			fmt.Printf("%s[!] Update failed: %v%s\n", config.Red, err, config.Reset)
			os.Exit(1)
		}
		return
	}

	if opts.Web {
		if err := web.Run(opts.WebAddr); err != nil {
			fmt.Printf("%s[!] Web server error: %v%s\n", config.Red, err, config.Reset)
			os.Exit(1)
		}
		return
	}

	if opts.UseXDP && runtime.GOOS != "linux" {
		fmt.Printf("%s[!] Error: The --ebpf option is only supported on Linux.%s\n", config.Red, config.Reset)
		fmt.Printf("%s[*] On this OS, please use a different scan type like -sT (TCP Connect) or remove the --ebpf flag.%s\n", config.Cyan, config.Reset)
		os.Exit(1)
	}

	isRawScan := opts.SynScan || opts.AckScan || opts.WindowScan || opts.NullScan || opts.FinScan || opts.XmasScan
	if isRawScan && runtime.GOOS == "linux" && !opts.UseXDP {
		fmt.Printf("%s[!] Warning: Raw packet scans (-sS, -sA, etc.) on Linux without --ebpf can be unreliable due to kernel interference.%s\n", config.Yellow, config.Reset)
		fmt.Printf("%s[*] Tip: For best results, add --ebpf to use the high-performance XDP engine.%s\n", config.Cyan, config.Reset)
	}

	if opts.VulnersAPIKey != "" && !opts.ServiceDetect {
		fmt.Printf("%s[!] Warning: --vulners-apikey was provided without -sV. CVE lookup requires service detection.%s\n", config.Yellow, config.Reset)
		fmt.Printf("%s[*] Tip: Add -sV to your command to enable service detection and CVE lookup.%s\n", config.Cyan, config.Reset)
	}

	if opts.DecoyIPs != "" {

		isSpoofableScan := opts.SynScan || opts.AckScan || opts.WindowScan || opts.NullScan || opts.FinScan || opts.XmasScan || opts.UdpScan || opts.ZombieHost != ""
		if isSpoofableScan {
			fmt.Printf("%s[*] Decoy scan enabled. Target will also see packets from: %s%s\n", config.Cyan, opts.DecoyIPs, config.Reset)
		} else {
			fmt.Printf("%s[!] Warning: Decoy scanning is only effective with raw packet scan types (e.g., -sS, -sU, -sA) and will be ignored for TCP Connect scans (-sT).%s\n", config.Yellow, config.Reset)
		}
	}

	if opts.RelayServer != "" {
		fmt.Printf("%s[*] Relay server enabled: %s%s\n", config.Cyan, opts.RelayServer, config.Reset)
		fmt.Printf("%s[!] Warning: When using --relay-server, tcpcat sends encapsulated packets to the relay.%s\n", config.Yellow, config.Reset)
		fmt.Printf("%s[!] Warning: Direct responses from the target will not be received. Scan results may be unreliable or show as FILTERED.%s\n", config.Yellow, config.Reset)
		fmt.Printf("%s[*] Tip: This mode is primarily for bypassing local uRPF filters on outgoing traffic.%s\n", config.Cyan, config.Reset)
	}

	var rawTargets []string

	if opts.Target != "" {
		rawTargets = append(rawTargets, opts.Target)
	}

	if opts.InputFile != "" {
		fileTargets, err := target.LoadFromFile(opts.InputFile)
		if err != nil {
			fmt.Printf("%s[!] Input File Error: %v%s\n", config.Red, err, config.Reset)
			os.Exit(1)
		}
		rawTargets = append(rawTargets, fileTargets...)
	}

	if opts.AWSTags != "" {
		fmt.Printf("%s[*] Loading targets from AWS EC2 tags...%s\n", config.White, config.Reset)
		awsTargets, err := target.LoadFromAWSTags(opts.AWSRegion, opts.AWSTags)
		if err != nil {
			fmt.Printf("%s[!] AWS Target Error: %v%s\n", config.Red, err, config.Reset)
			os.Exit(1)
		}
		rawTargets = append(rawTargets, awsTargets...)
	}

	if len(rawTargets) == 0 {
		fmt.Printf("%s[!] Error: No target specified.%s\n", config.Red, config.Reset)
		flag.Usage()
		os.Exit(1)
	}

	targetIPs, err := target.ParseTargets(rawTargets)
	if err != nil {
		fmt.Printf("%s[!] Target Error: %v%s\n", config.Red, err, config.Reset)
		os.Exit(1)
	}
	if opts.ScopeFile != "" {
		targetIPs, err = target.FilterByScope(targetIPs, opts.ScopeFile)
		if err != nil {
			fmt.Printf("%s[!] Scope Error: %v%s\n", config.Red, err, config.Reset)
			os.Exit(1)
		}
		if len(targetIPs) == 0 {
			fmt.Printf("%s[!] Scope Error: no resolved targets are authorized by %s.%s\n", config.Red, opts.ScopeFile, config.Reset)
			os.Exit(1)
		}
	}

	displayTarget := opts.Target
	if displayTarget == "" {
		displayTarget = opts.InputFile
	}
	if displayTarget == "" && opts.AWSTags != "" {
		displayTarget = fmt.Sprintf("AWS Tags in %s", opts.AWSRegion)
	}

	fmt.Printf("%s[*] Target loaded: %s%s (%d IP(s) resolved)%s\n",
		config.Bold, config.Red, displayTarget, len(targetIPs), config.Reset)

	if opts.Traceroute {
		fmt.Printf("%s[*] Executing TCP Traceroute to %s...%s\n", config.Yellow, targetIPs[0], config.Reset)
		fmt.Printf("%s%-4s %-25s %-30s %-10s%s\n", config.Bold, "Hop", "IP Address", "Hostname", "Latency", config.Reset)
		fmt.Println(config.Bold + "───────────────────────────────────────────────────────────────────────────" + config.Reset)

		hops := discovery.RunTraceroute(targetIPs[0], 80, 30, 2*time.Second)
		for _, h := range hops {
			ipDisp := h.IP
			if ipDisp == "*" {
				fmt.Printf("%s%-4d %-25s %-30s %-10s%s\n", config.Red, h.Hop, "*", "*", "Timeout", config.Reset)
			} else {
				fmt.Printf("%s%-4d %s%-25s%s %-30s %s%.2f ms%s\n",
					config.Cyan, h.Hop, config.White, ipDisp, config.Reset, h.Hostname, config.Bold, h.LatencyMs, config.Reset)
			}
		}
		os.Exit(0)
	}

	var activeTargets []string
	if opts.SkipDiscovery {
		activeTargets = targetIPs
		fmt.Printf("%s[*] Host discovery skipped (-Pn). All %d target(s) will be scanned.%s\n", config.Yellow, len(targetIPs), config.Reset)
	} else {
		fmt.Printf("%s[*] Running Host Discovery...%s\n", config.White, config.Reset)

		var wg sync.WaitGroup
		var mu sync.Mutex

		if opts.UnsafeNoLimits {
			fmt.Printf("%s[!] Running host discovery with unlimited concurrency (--unsafe-no-limits). This may crash your system.%s\n", config.Red, config.Reset)
			for _, ip := range targetIPs {
				wg.Add(1)
				go func(ip string) {
					defer wg.Done()
					if discovery.DiscoverHost(ip, opts.UdpPing, 2*time.Second) {
						mu.Lock()
						activeTargets = append(activeTargets, ip)
						mu.Unlock()
						fmt.Printf("    ├─ %s[UP]%s %s\n", config.Green, config.Reset, ip)
					} else if opts.Verbose {
						fmt.Printf("    ├─ %s[DOWN]%s %s\n", config.Red, config.Reset, ip)
					}
				}(ip)
			}
		} else {
			sem := make(chan struct{}, opts.MaxWorkers)

			var limiter *time.Ticker
			if opts.RateLimit > 0 {
				limiter = time.NewTicker(time.Second / time.Duration(opts.RateLimit))
				defer limiter.Stop()
			}

			for _, ip := range targetIPs {
				if limiter != nil {
					<-limiter.C
				}
				wg.Add(1)
				sem <- struct{}{}

				go func(ip string) {
					defer wg.Done()
					defer func() { <-sem }()

					if discovery.DiscoverHost(ip, opts.UdpPing, 2*time.Second) {
						mu.Lock()
						activeTargets = append(activeTargets, ip)
						mu.Unlock()
						fmt.Printf("    ├─ %s[UP]%s %s\n", config.Green, config.Reset, ip)
					} else if opts.Verbose {
						fmt.Printf("    ├─ %s[DOWN]%s %s\n", config.Red, config.Reset, ip)
					}
				}(ip)
			}
		}

		wg.Wait()

		if len(activeTargets) == 0 {
			fmt.Printf("%s[!] No active hosts found. Use -Pn to skip host discovery.%s\n", config.Yellow, config.Reset)
			os.Exit(0)
		}
	}

	if opts.PingScan {
		fmt.Printf("%s[✓] Host discovery complete. %d/%d host(s) up.%s\n",
			config.Green, len(activeTargets), len(targetIPs), config.Reset)
		os.Exit(0)
	}

	targetedPorts, err := ports.ParsePorts(opts.Ports, opts.TopPorts)
	if err != nil {
		fmt.Printf("%s[!] Port Parsing Error: %v%s\n", config.Red, err, config.Reset)
		os.Exit(1)
	}

	fmt.Printf("%s[*] Ports loaded: %d port(s) targeted%s\n", config.White, len(targetedPorts), config.Reset)
	fmt.Println(config.Bold + "───────────────────────────────────────────────────────────────────────────" + config.Reset)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n%s[!] Scan interrupted by user.%s\n", config.Yellow, config.Reset)
		if opts.UseXDP && runtime.GOOS == "linux" {
			scan.ShutdownXDPEngine()
		}
		os.Exit(1)
	}()

	if opts.UseXDP {
		fmt.Printf("%s[*] Booting experimental AF_XDP Engine...%s\n", config.Yellow, config.Reset)

		xsk, err := scan.InitXDPEngine()
		if err != nil {
			fmt.Printf("%s[!] Fatal XDP Error: %v%s\n", config.Red, err, config.Reset)
			os.Exit(1)
		}

		scan.GlobalXsk = xsk
		defer scan.ShutdownXDPEngine()
	}

	t0 := time.Now()
	engine := scan.NewEngine(opts)
	if engine == nil {
		fmt.Printf("%s[!] Failed to initialize scan engine. Exiting.%s\n", config.Red, config.Reset)
		os.Exit(1)
	}

	scan.ApplyEvasionOptions(engine, opts)

	if opts.EvasionMode != "off" {
		fmt.Printf("%s[*] Evasion Mode: %s (Jitter: %.1f%%, Fragmentation: %v)%s\n",
			config.Red, opts.EvasionMode, opts.Jitter*100, opts.Fragment, config.Reset)
	}

	results := engine.Execute(activeTargets, targetedPorts)

	if opts.DeepInspect || opts.ProtocolTracing || opts.TimingAnalysis {
		fmt.Println(config.Bold + "───────────────────────────────────────────────────────────────────────────" + config.Reset)
		fmt.Printf("%s[*] Running Deep Packet Inspection...%s\n", config.Yellow, config.Reset)
		osiV := opts.OSIVerbosity
		if osiV == 0 {
			osiV = 4
		}
		for _, r := range results {
			if r.State == scan.StateOpen {
				scan.RunDeepInspect(r.IP, r.Port, osiV, opts.HexDump, opts.ProtocolTracing, opts.TimingAnalysis)
			}
		}
	}

	if opts.ServiceDetect {
		fmt.Println(config.Bold + "───────────────────────────────────────────────────────────────────────────" + config.Reset)
		fmt.Printf("%s[*] Running Service & Version Detection...%s\n", config.Red, config.Reset)
		for i := range results {
			if results[i].State == scan.StateOpen {
				svc := service.DetectService(results[i].IP, results[i].Port, 2*time.Second, opts.InsecureTLS)
				results[i].Service = svc.Name
				results[i].Banner = svc.Banner
				results[i].Version = svc.Version

				bannerDisp := ""
				if svc.Banner != "" {
					bannerDisp = fmt.Sprintf(" | banner=[%s]", svc.Banner)
				}
				osDisp := ""
				if svc.OS != "unknown" {
					osDisp = fmt.Sprintf(" (OS: %s)", svc.OS)
				}
				results[i].OS = svc.OS
				fmt.Printf("%s[v] %s:%-5d ─ SERVICE: %s%s %s%s%s%s\n",
					config.Bold, results[i].IP, results[i].Port, config.Bold, svc.Name, svc.Version, osDisp, config.Reset, bannerDisp)
			}
		}

		var vulnScanner vuln.Scanner
		var err error
		var offlineScanner *vuln.OfflineScanner
		offlineScanner, offlineErr := vuln.NewOfflineScanner()
		if offlineErr != nil {
			fmt.Printf("%s[!] Could not load offline vulnerability database: %v%s\n", config.Red, offlineErr, config.Reset)
		}

		if opts.VulnersAPIKey != "" {
			vulnScanner, err = vuln.NewVulnersScanner(opts.VulnersAPIKey)
		} else {
			vulnScanner = offlineScanner
		}

		if err != nil {
			fmt.Printf("%s[!] Error initializing vulnerability scanner: %v%s\n", config.Red, err, config.Reset)
		} else if vulnScanner == nil {
			fmt.Printf("%s[!] No vulnerability scanner is available.%s\n", config.Red, config.Reset)
		} else {
			fmt.Println(config.Bold + "───────────────────────────────────────────────────────────────────────────" + config.Reset)
			fmt.Printf("%s[*] Running Vulnerability Lookup (Source: %s)...%s\n", config.Red, vulnScanner.SourceName(), config.Reset)

			for i := range results {
				r := &results[i]
				if r.State != scan.StateOpen {
					continue
				}

				r.Assessment = scan.VulnerabilityAssessment{
					Status:     "not_assessed",
					Source:     vulnScanner.SourceName(),
					AssessedAt: time.Now().UTC(),
				}
				if r.Service == "unknown" || r.Version == "" {
					r.Assessment.Reason = "No reliable service version was detected."
					continue
				}

				if r.Service != "unknown" && r.Version != "" {
					allVulnerabilities, err := vulnScanner.GetForSoftware(r.Service, r.Version)

					if err != nil && offlineScanner != nil {
						fmt.Printf("    %s[~] OSV lookup failed, falling back to offline DB for %s:%d%s\n", config.Yellow, r.IP, r.Port, config.Reset)
						allVulnerabilities, err = offlineScanner.GetForSoftware(r.Service, r.Version)
					}

					if err != nil {
						r.Assessment.Status = "error"
						r.Assessment.Reason = fmt.Sprintf("Vulnerability lookup failed for %s %s: %v", r.Service, r.Version, err)
						continue
					}

					initialCount := len(allVulnerabilities)
					vulnerabilities := vuln.FilterRelevantCVEs(allVulnerabilities, r.OS)
					filteredCount := initialCount - len(vulnerabilities)

					sort.Slice(vulnerabilities, func(i, j int) bool {
						return vulnerabilities[i].CVSS > vulnerabilities[j].CVSS
					})
					vulnerabilities = vuln.Enrich(vulnerabilities)
					r.Vulnerabilities = vulnerabilities
					if len(vulnerabilities) > 0 {
						r.RiskSeverity = vulnerabilities[0].Severity
						r.Assessment.Status = "matched"
						r.Assessment.Reason = fmt.Sprintf("Matched %s %s against %s.", r.Service, r.Version, vulnScanner.SourceName())
					} else {
						r.Assessment.Status = "no_match"
						r.Assessment.Reason = fmt.Sprintf("No matching vulnerabilities were found for %s %s.", r.Service, r.Version)
					}

					if len(vulnerabilities) > 0 {
						fmt.Printf("%s[!] %s:%-5d - %d CVEs found for %s %s%s\n", config.Red, r.IP, r.Port, len(vulnerabilities), r.Service, r.Version, config.Reset)
						for _, v := range vulnerabilities {
							var cvssColor string
							switch {
							case v.CVSS >= 9.0:
								cvssColor = config.Red
							case v.CVSS >= 7.0:
								cvssColor = config.Yellow
							case v.CVSS >= 4.0:
								cvssColor = config.Cyan
							default:
								cvssColor = config.White
							}
							fmt.Printf("    |_ %s (%sCVSS: %.1f%s) - %s\n", v.ID, cvssColor, v.CVSS, config.Reset, v.Title)
						}
						if filteredCount > 0 {
							fmt.Printf("    %s[~] %d CVEs filtered by OS (%s)%s\n", config.Yellow, filteredCount, r.OS, config.Reset)
						}
					} else if initialCount > 0 {
						fmt.Printf("%s[+] %s:%-5d - 0 CVEs found after strict version filtering.%s\n", config.Green, r.IP, r.Port, config.Reset)
					}
				}
			}
		}
	}

	duration := time.Since(t0)

	openCount := 0
	for _, r := range results {
		if r.State == scan.StateOpen {
			openCount++
		}
	}

	fmt.Println(config.Bold + "───────────────────────────────────────────────────────────────────────────" + config.Reset)
	fmt.Printf("%s[✓] Scan completed in %v. Found %d open port(s) across %d active target(s).%s\n",
		config.Green, duration.Round(time.Millisecond), openCount, len(activeTargets), config.Reset)

	if opts.JsonOutput != "" {
		err := output.ExportJSON(opts.JsonOutput, opts.Target, results, duration)
		if err != nil {
			fmt.Printf("%s[!] Failed to export JSON: %v%s\n", config.Red, err, config.Reset)
		} else {
			fmt.Printf("%s[✓] Results exported to JSON file: %s%s\n", config.Green, opts.JsonOutput, config.Reset)
		}
	}
	if opts.AuditLog != "" {
		auditOptions := output.AuditOptions{
			Profile:   opts.Profile,
			ScopeFile: opts.ScopeFile,
			Ports:     opts.Ports,
			TopPorts:  opts.TopPorts,
			Timing:    opts.Timing,
			RateLimit: opts.RateLimit,
		}
		if err := output.ExportAuditJSONL(opts.AuditLog, displayTarget, auditOptions, results, duration); err != nil {
			fmt.Printf("%s[!] Failed to write audit log: %v%s\n", config.Red, err, config.Reset)
		}
	}
	if opts.SARIFOutput != "" {
		if err := output.ExportSARIF(opts.SARIFOutput, results); err != nil {
			fmt.Printf("%s[!] Failed to export SARIF: %v%s\n", config.Red, err, config.Reset)
		}
	}
	if opts.BaselineFile != "" {
		baseline, err := compare.LoadBaseline(opts.BaselineFile)
		if err != nil {
			fmt.Printf("%s[!] Failed to load baseline: %v%s\n", config.Red, err, config.Reset)
		} else {
			changes := compare.Compare(results, baseline)
			fmt.Printf("%s[*] Comparison: %d new open port(s), %d service change(s), %d new CVE(s).%s\n", config.Cyan, len(changes.NewOpenPorts), len(changes.ServiceChanges), len(changes.NewVulnerabilities), config.Reset)
			if opts.ChangesOutput != "" {
				if err := compare.WriteReport(opts.ChangesOutput, changes); err != nil {
					fmt.Printf("%s[!] Failed to write comparison report: %v%s\n", config.Red, err, config.Reset)
				}
			}
		}
	}
}
