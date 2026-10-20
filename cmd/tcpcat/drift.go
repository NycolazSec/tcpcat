package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/drift"
	"github.com/NycolazSec/tcpcat/internal/inventory"
)

const driftUsage = `Compare two inventories of the same host and report what opened up.

  Take an inventory now and again later (on the host, as root):
      tcpcat inventory -o day0.json
      # ... a week, a deploy, an update later ...
      tcpcat inventory -o day7.json
  Then diff them, anywhere:
      tcpcat drift day0.json day7.json

  It flags every port that started listening, stopped, widened from loopback
  to every interface, or changed owner. Ports newly reachable from outside
  come first.

  -j <file>   also write the diff as JSON
  --exposed-only   list only the changes that increased outside exposure

  Exit status: 0 nothing became externally reachable, 1 something did, 2 error.
`

func runDrift(args []string) int {
	fs := flag.NewFlagSet("drift", flag.ContinueOnError)
	jsonOut := fs.String("j", "", "Write the diff as JSON")
	exposedOnly := fs.Bool("exposed-only", false, "Show only changes that increased outside exposure")
	fs.Usage = func() { fmt.Print(driftUsage) }
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 2 {
		fmt.Print(driftUsage)
		return exitError
	}

	before, err := inventory.Load(fs.Arg(0))
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	after, err := inventory.Load(fs.Arg(1))
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return exitError
	}

	rep := drift.Diff(before, after)
	renderDrift(rep, *exposedOnly)

	if *jsonOut != "" {
		data, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*jsonOut, append(data, '\n'), 0600); err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
		fmt.Printf("  %sJSON diff written to %s%s\n", config.Gray, *jsonOut, config.Reset)
	}

	if rep.NewlyExposed() > 0 {
		return exitViolation
	}
	return exitOK
}

func renderDrift(rep drift.Report, exposedOnly bool) {
	bar := config.Bold + "────────────────────────────────────────────────────────────────────────────────" + config.Reset
	fmt.Println(bar)
	fmt.Printf("  HOST     %s%s%s\n", config.Bold+config.White, rep.Host, config.Reset)
	fmt.Printf("  WINDOW   %s → %s\n", rep.From.Format("2006-01-02 15:04"), rep.To.Format("2006-01-02 15:04 MST"))
	fmt.Println(bar)

	tag := map[string]string{
		"high":   config.Red + "NEWLY EXPOSED" + config.Reset,
		"medium": config.White + "CHANGED      " + config.Reset,
		"info":   config.Gray + "info         " + config.Reset,
	}
	shown := 0
	for _, c := range rep.Changes {
		if exposedOnly && c.Severity != "high" {
			continue
		}
		shown++
		fmt.Printf("\n  %s  %s%d/tcp%s  %s\n", tag[c.Severity], config.Bold, c.Port, config.Reset, c.Note)
		if c.Before != "" {
			fmt.Printf("     was:  %s\n", c.Before)
		}
		if c.After != "" {
			fmt.Printf("     now:  %s\n", c.After)
		}
	}
	if shown == 0 {
		fmt.Printf("\n  %sNo change in exposure between the two snapshots.%s\n", config.Gray, config.Reset)
	}

	fmt.Println("\n" + bar)
	if n := rep.NewlyExposed(); n > 0 {
		fmt.Printf("  %s✗ %d port(s) became reachable from outside since the first snapshot.%s\n", config.Bold+config.Red, n, config.Reset)
	} else {
		fmt.Printf("  %s✓ Nothing became reachable from outside.%s\n", config.White, config.Reset)
	}
	fmt.Println(bar)
}
