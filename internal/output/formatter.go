package output

import (
	"fmt"
	"strings"
	"time"

	"tcpcat/config"
	"tcpcat/internal/scan"
)

func PrintProfessionalHeader() {
	fmt.Printf("%s%s%s\n", config.Reset, "\n", config.Bold)
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Printf("║%s  TCPCAT v1.0  %s│  Network Security & Reconnaissance Engine      %s║\n",
		config.Red, config.White, config.Reset)
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Printf("%s\n", config.Reset)
}

func PrintScanConfiguration(target string, ports string, scanType string) {
	fmt.Printf("\n%s┌─ SCAN CONFIGURATION%s\n", config.Red, config.Reset)
	fmt.Printf("%s│  Target%s: %s%s%s\n", config.Red, config.Reset, config.Bold, target, config.Reset)
	fmt.Printf("%s│  Ports%s:  %s%s%s\n", config.Red, config.Reset, config.Bold, ports, config.Reset)
	fmt.Printf("%s│  Type%s:   %s%s%s\n", config.Red, config.Reset, config.Bold, scanType, config.Reset)
	fmt.Printf("%s└──────────────────────────────────────────────────────────────────────────\n%s\n", config.Red, config.Reset)
}

func PrintDivider() {
	fmt.Printf("%s═══════════════════════════════════════════════════════════════════════════\n%s", config.Red, config.Reset)
}

func PrintSectionHeader(title string) {
	fmt.Printf("\n%s┌─ %s%s\n", config.Red, title, config.Reset)
	fmt.Printf("%s│%s\n", config.Red, config.Reset)
}

func PrintSectionEnd() {
	fmt.Printf("%s└────────────────────────────────────────────────────────────────────────────\n%s\n", config.Red, config.Reset)
}

func FormatPortState(state string) string {
	switch state {
	case scan.StateOpen:
		return fmt.Sprintf("%s%s%s", config.Red, "● OPEN", config.Reset)
	case scan.StateClosed:
		return fmt.Sprintf("%s%s%s", config.White, "○ CLOSED", config.Reset)
	case scan.StateFiltered:
		return fmt.Sprintf("%s%s%s", config.Yellow, "◌ FILTERED", config.Reset)
	case scan.StateOpenFiltered:
		return fmt.Sprintf("%s%s%s", config.Cyan, "◐ OPEN|FILTERED", config.Reset)
	default:
		return state
	}
}

func PrintPortResults(results []scan.TargetResult) {
	if len(results) == 0 {
		return
	}

	PrintSectionHeader("PORT SCAN RESULTS")

	openPorts := []scan.TargetResult{}
	closedPorts := []scan.TargetResult{}
	filteredPorts := []scan.TargetResult{}

	for _, r := range results {
		switch r.State {
		case scan.StateOpen:
			openPorts = append(openPorts, r)
		case scan.StateClosed:
			closedPorts = append(closedPorts, r)
		case scan.StateFiltered:
			filteredPorts = append(filteredPorts, r)
		}
	}

	if len(openPorts) > 0 {
		fmt.Printf("%s▶ OPEN PORTS (%d)%s\n", config.Red, len(openPorts), config.Reset)
		for _, r := range openPorts {
			reasonStr := ""
			if r.Reason != "" {
				reasonStr = fmt.Sprintf("  [%s%s%s]", config.Yellow, r.Reason, config.Reset)
			}
			fmt.Printf("  %s%s:%-6d%s   Latency: %s%.2f ms%s%s\n",
				config.Bold, r.IP, r.Port, config.Reset,
				config.White, r.LatencyMs, config.Reset, reasonStr)
		}
	}

	if len(filteredPorts) > 0 {
		fmt.Printf("\n%s▶ FILTERED PORTS (%d)%s\n", config.Yellow, len(filteredPorts), config.Reset)
		for _, r := range filteredPorts {
			reasonStr := ""
			if r.Reason != "" {
				reasonStr = fmt.Sprintf("  [%s%s%s]", config.Cyan, r.Reason, config.Reset)
			}
			fmt.Printf("  %s%s:%-6d%s   Latency: %s%.2f ms%s%s\n",
				config.Bold, r.IP, r.Port, config.Reset,
				config.White, r.LatencyMs, config.Reset, reasonStr)
		}
	}

	if len(closedPorts) > 0 && len(closedPorts) <= 10 {
		fmt.Printf("\n%s▶ CLOSED PORTS (%d)%s\n", config.White, len(closedPorts), config.Reset)
		for _, r := range closedPorts {
			fmt.Printf("  %s%s:%-6d%s   Latency: %s%.2f ms%s\n",
				config.Bold, r.IP, r.Port, config.Reset,
				config.White, r.LatencyMs, config.Reset)
		}
	} else if len(closedPorts) > 10 {
		fmt.Printf("\n%s▶ CLOSED PORTS (%d - hiding for brevity)%s\n", config.White, len(closedPorts), config.Reset)
	}

	PrintSectionEnd()
}

func PrintServiceDetection(results []scan.TargetResult, filteredCount int) {
	openWithService := []scan.TargetResult{}

	for _, r := range results {
		if r.State == scan.StateOpen && r.Service != "" && r.Service != "unknown" {
			openWithService = append(openWithService, r)
		}
	}

	if len(openWithService) == 0 && filteredCount == 0 {
		return
	}

	PrintSectionHeader("SERVICE DETECTION")

	if filteredCount > 0 {
		fmt.Printf("%s[~] %d FILTERED port(s) skipped%s (service detection requires OPEN state)\n",
			config.Yellow, filteredCount, config.Reset)
	}

	if len(openWithService) > 0 {
		fmt.Printf("%s%s\n", config.Bold, "Service Name                    Port      Version")
		fmt.Printf("%s%s\n", config.Red, strings.Repeat("─", 70))
		for _, r := range openWithService {
			version := r.Version
			if version == "" {
				version = "(unknown)"
			}
			banner := ""
			if r.Banner != "" && len(r.Banner) > 0 {
				banner = fmt.Sprintf(" [%s%s%s]", config.Cyan, r.Banner, config.Reset)
			}
			fmt.Printf("%-30s %5d    %s%s%s%s\n",
				r.Service, r.Port, config.White, version, config.Reset, banner)
		}
	}

	PrintSectionEnd()
}

func PrintVulnerabilityResults(results []scan.TargetResult) {
	vulnCount := 0
	for _, r := range results {

		if r.State == scan.StateOpen && r.Service != "unknown" {
			vulnCount++
		}
	}

	if vulnCount == 0 {
		return
	}

	PrintSectionHeader("VULNERABILITY SCAN")
	fmt.Printf("%s[i] CVE lookup requires additional configuration (--vulners-apikey)%s\n",
		config.Yellow, config.Reset)
	PrintSectionEnd()
}

func PrintSummary(results []scan.TargetResult, duration time.Duration, targets int) {
	openCount := 0
	closedCount := 0
	filteredCount := 0

	for _, r := range results {
		switch r.State {
		case scan.StateOpen:
			openCount++
		case scan.StateClosed:
			closedCount++
		case scan.StateFiltered:
			filteredCount++
		}
	}

	fmt.Printf("\n%s┌─ SCAN SUMMARY%s\n", config.Red, config.Reset)
	fmt.Printf("%s│%s\n", config.Red, config.Reset)
	fmt.Printf("%s│  %s✓ Scan completed%s in %s%v%s\n",
		config.Red, config.Green, config.Reset, config.Bold, duration.Round(time.Millisecond), config.Reset)
	fmt.Printf("%s│  %s● Open ports%s:     %s%d%s\n",
		config.Red, config.Red, config.Reset, config.Bold, openCount, config.Reset)
	fmt.Printf("%s│  %s○ Closed ports%s:   %s%d%s\n",
		config.Red, config.White, config.Reset, config.Bold, closedCount, config.Reset)
	fmt.Printf("%s│  %s◌ Filtered ports%s:  %s%d%s\n",
		config.Red, config.Yellow, config.Reset, config.Bold, filteredCount, config.Reset)
	fmt.Printf("%s│  %sTargets scanned%s:  %s%d%s\n",
		config.Red, config.Cyan, config.Reset, config.Bold, targets, config.Reset)
	fmt.Printf("%s│%s\n", config.Red, config.Reset)
	fmt.Printf("%s└──────────────────────────────────────────────────────────────────────────\n%s\n", config.Red, config.Reset)
}

func PrintWarning(msg string) {
	fmt.Printf("%s[!] %s%s\n", config.Yellow, msg, config.Reset)
}

func PrintInfo(msg string) {
	fmt.Printf("%s[*] %s%s\n", config.Cyan, msg, config.Reset)
}

func PrintSuccess(msg string) {
	fmt.Printf("%s[✓] %s%s\n", config.Green, msg, config.Reset)
}

func PrintError(msg string) {
	fmt.Printf("%s[✗] %s%s\n", config.Red, msg, config.Reset)
}
