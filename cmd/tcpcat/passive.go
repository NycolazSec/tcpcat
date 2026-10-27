package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/passive"
)

// runPassive implements `tcpcat passive`: passive, traffic-driven discovery of
// what this host listens on and who it talks to, using an eBPF tracepoint on
// the kernel's TCP state machine. It sends nothing on the network.
func runPassive(args []string) int {
	fs := flag.NewFlagSet("passive", flag.ContinueOnError)
	duration := fs.Duration("duration", 30*time.Second, "how long to observe before reporting (0 = until Ctrl-C)")
	asJSON := fs.Bool("json", false, "emit the observed flows as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if err := passive.Supported(); err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return 1
	}

	// Cancel on either the observation window elapsing or Ctrl-C, whichever
	// comes first. A zero duration means "run until interrupted".
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if *duration > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), *duration)
		defer cancel()
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	if !*asJSON {
		window := "until interrupted"
		if *duration > 0 {
			window = (*duration).String()
		}
		fmt.Printf("%s[*] Passively observing TCP activity (%s). No packets are sent.%s\n",
			config.Red, window, config.Reset)
	}

	flows, err := passive.Watch(ctx)
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(flows); err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return 1
		}
		return 0
	}

	printPassive(flows)
	return 0
}

func printPassive(flows []passive.Flow) {
	var listens, conns []passive.Flow
	for _, f := range flows {
		if f.Kind == "listen" {
			listens = append(listens, f)
		} else {
			conns = append(conns, f)
		}
	}

	bar := config.Bold + "────────────────────────────────────────────────────────────────────────────────" + config.Reset
	fmt.Println(bar)
	if len(listens) == 0 && len(conns) == 0 {
		fmt.Printf("%s[~] No TCP activity observed in the window.%s\n", config.White, config.Reset)
		return
	}

	if len(listens) > 0 {
		fmt.Printf("%s[*] Listening sockets observed:%s\n", config.Bold, config.Reset)
		for _, f := range listens {
			fmt.Printf("    %s%s:%d%s\n", config.White, f.LocalIP, f.LocalPort, config.Reset)
		}
	}

	if len(conns) > 0 {
		fmt.Printf("%s[*] Connections observed:%s\n", config.Bold, config.Reset)
		for _, f := range conns {
			// Inbound reaches a local service from outside -- the exposure that
			// usually matters most -- so it gets the attention colour.
			color := config.Gray
			arrow := "→"
			if f.Direction == "inbound" {
				color, arrow = config.Red, "←"
			}
			fmt.Printf("    %s%-8s%s %s%s:%d %s %s:%d%s (x%d)\n",
				color, f.Direction, config.Reset,
				config.White, f.LocalIP, f.LocalPort,
				arrow, f.RemoteIP, f.RemotePort, config.Reset, f.Count)
		}
	}
	fmt.Println(bar)
	fmt.Printf("%s[✓] %d listening socket(s), %d connection relationship(s) observed.%s\n",
		config.White, len(listens), len(conns), config.Reset)
}
