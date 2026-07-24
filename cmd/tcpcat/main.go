// cmd/tcpcat/main.go
package main

import (
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "time"

    "tcpcat/config"
    "tcpcat/internal/discovery"
    "tcpcat/internal/evasion"
    "tcpcat/internal/output"
    "tcpcat/internal/ports"
    "tcpcat/internal/scan"
    "tcpcat/internal/service"
    "tcpcat/internal/target"
)

func main() {
    opts, err := config.ParseFlags()
    if err != nil {
        fmt.Printf("%s[!] Configuration error: %v%s\n", config.Red, err, config.Reset)
        os.Exit(1)
    }

    fmt.Println(config.Banner)

    // Accumulate raw targets (direct argument + -iL file)
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

    if len(rawTargets) == 0 {
        fmt.Printf("%s[!] Error: No target specified.%s\n", config.Red, config.Reset)
        os.Exit(1)
    }

    // Global target resolution
    targetIPs, err := target.ParseTargets(rawTargets)
    if err != nil {
        fmt.Printf("%s[!] Target Error: %v%s\n", config.Red, err, config.Reset)
        os.Exit(1)
    }

    // Initialize evasion configuration
    _, err = evasion.NewConfig(opts.SourcePort, opts.TTL, opts.DataString, opts.DataHex, "")
    if err != nil {
        fmt.Printf("%s[!] Evasion config error: %v%s\n", config.Red, err, config.Reset)
        os.Exit(1)
    }

    displayTarget := opts.Target
    if displayTarget == "" {
        displayTarget = opts.InputFile
    }

    fmt.Printf("%s[*] Target loaded: %s%s (%d IP(s) resolved)%s\n",
        config.Bold, config.Cyan, displayTarget, len(targetIPs), config.Reset)

    // Traceroute Mode
    if opts.Traceroute {
        fmt.Printf("%s[*] Executing TCP Traceroute to %s...%s\n", config.Yellow, targetIPs[0], config.Reset)
        fmt.Printf("%s%-4s %-25s %-30s %-10s%s\n", config.Bold, "Hop", "IP Address", "Hostname", "Latency", config.Reset)
        fmt.Println(config.Cyan + "───────────────────────────────────────────────────────────────────────────" + config.Reset)

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

    // Host Discovery
    var activeTargets []string
    if opts.SkipDiscovery {
        activeTargets = targetIPs
    } else {
        fmt.Printf("%s[*] Running Host Discovery...%s\n", config.White, config.Reset)
        for _, ip := range targetIPs {
            if discovery.PingHost(ip, 1*time.Second) {
                activeTargets = append(activeTargets, ip)
                fmt.Printf("    ├─ %s[UP]%s %s\n", config.Green, config.Reset, ip)
            } else {
                if opts.Verbose {
                    fmt.Printf("    ├─ %s[DOWN]%s %s\n", config.Red, config.Reset, ip)
                }
            }
        }
        if len(activeTargets) == 0 {
            fmt.Printf("%s[!] No active hosts found. Use -Pn to skip host discovery.%s\n", config.Yellow, config.Reset)
            os.Exit(0)
        }
    }

    // Ping Scan only mode (-sn)
    if opts.PingScan {
        fmt.Printf("%s[✓] Host discovery complete. %d/%d host(s) up.%s\n",
            config.Green, len(activeTargets), len(targetIPs), config.Reset)
        os.Exit(0)
    }

    // Port Parsing
    targetedPorts, err := ports.ParsePorts(opts.Ports, opts.TopPorts)
    if err != nil {
        fmt.Printf("%s[!] Port Parsing Error: %v%s\n", config.Red, err, config.Reset)
        os.Exit(1)
    }

    fmt.Printf("%s[*] Ports loaded: %d port(s) targeted%s\n", config.White, len(targetedPorts), config.Reset)
    fmt.Println(config.Cyan + "───────────────────────────────────────────────────────────────────────────" + config.Reset)

    // Interrupt handling (Ctrl+C)
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-sigChan
        fmt.Printf("\n%s[!] Scan interrupted by user.%s\n", config.Yellow, config.Reset)
        os.Exit(0)
    }()

    // 💥 STARTING eBPF ENGINE (IF ENABLED) 💥
    if opts.UseXDP {
        fmt.Printf("%s[*] Booting experimental AF_XDP Engine...%s\n", config.Yellow, config.Reset)
        
        // We retrieve the initialized socket (without specifying "eth0", it handles it automatically)
        xsk, err := scan.InitXDPEngine()
        if err != nil {
            fmt.Printf("%s[!] Fatal XDP Error: %v%s\n", config.Red, err, config.Reset)
            os.Exit(1)
        }
        
        // We assign the socket to the global pointer so ScanXDPPort can use it
        scan.GlobalXsk = xsk 
    }

    // Execute Scan
    t0 := time.Now()
    engine := scan.NewEngine(opts)
    results := engine.Execute(activeTargets, targetedPorts)

    // Version / Service Detection (-sV) on open ports
    if opts.ServiceDetect {
        fmt.Println(config.Cyan + "───────────────────────────────────────────────────────────────────────────" + config.Reset)
        fmt.Printf("%s[*] Running Service & Version Detection (-sV)...%s\n", config.Yellow, config.Reset)
        for i := range results {
            if results[i].State == scan.StateOpen {
                svc := service.DetectService(results[i].IP, results[i].Port, 2*time.Second)
                results[i].Service = svc.Name
                results[i].Banner = svc.Banner

                bannerDisp := ""
                if svc.Banner != "" {
                    bannerDisp = fmt.Sprintf(" | banner=[%s]", svc.Banner)
                }
                fmt.Printf("%s[v] %s:%-5d ─ SERVICE: %s%s %s%s\n",
                    config.Cyan, results[i].IP, results[i].Port, config.Bold, svc.Name, config.Reset, bannerDisp)
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

    fmt.Println(config.Cyan + "───────────────────────────────────────────────────────────────────────────" + config.Reset)
    fmt.Printf("%s[✓] Scan completed in %v. Found %d open port(s) across %d active target(s).%s\n",
        config.Green, duration.Round(time.Millisecond), openCount, len(activeTargets), config.Reset)

    // JSON Export (-j)
    if opts.JsonOutput != "" {
        err := output.ExportJSON(opts.JsonOutput, opts.Target, results, duration)
        if err != nil {
            fmt.Printf("%s[!] Failed to export JSON: %v%s\n", config.Red, err, config.Reset)
        } else {
            fmt.Printf("%s[✓] Results exported to JSON file: %s%s\n", config.Green, opts.JsonOutput, config.Reset)
        }
    }
}