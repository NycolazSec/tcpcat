package scan

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"tcpcat/config"
	"tcpcat/internal/scripting"
)

type ScanJob struct {
	IP   string
	Port int
}

type Engine struct {
	opts         *config.Options
	timeout      time.Duration
	scriptEngine *scripting.ScriptingEngine
}

func NewEngine(opts *config.Options) *Engine {
	timeoutSec := 3.0 // Default T3
	if opts.Timing >= 0 && opts.Timing <= 5 {
		timeouts := []float64{15, 5, 3, 1, 0.5, 0.3}
		timeoutSec = timeouts[opts.Timing]
	}

	timeout := time.Duration(timeoutSec * float64(time.Second))
	var se *scripting.ScriptingEngine
	if opts != nil && opts.ScriptPath != "" {
		var err error
		se, err = scripting.New(opts.ScriptPath, timeout)
		if err != nil {
			fmt.Printf("%s[!] Error initializing script engine: %v%s\n", config.Red, err, config.Reset)
		}
	}

	return &Engine{
		opts:         opts,
		timeout:      timeout,
		scriptEngine: se,
	}
}

func (e *Engine) Execute(targets []string, ports []int) []TargetResult {
	jobs := make(chan ScanJob, len(targets)*len(ports))
	resultsChan := make(chan TargetResult, len(targets)*len(ports))
	var allResults []TargetResult

	var wg sync.WaitGroup
	for i := 0; i < e.opts.MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				res := e.dispatchScan(job.IP, job.Port)
				resultsChan <- res
			}
		}()
	}

	for _, ip := range targets {
		for _, port := range ports {
			jobs <- ScanJob{IP: ip, Port: port}
		}
	}
	close(jobs)

	wg.Wait()
	close(resultsChan)

	for res := range resultsChan {
		allResults = append(allResults, res)
	}

	sort.Slice(allResults, func(i, j int) bool {
		if allResults[i].IP != allResults[j].IP {
			return allResults[i].IP < allResults[j].IP
		}
		return allResults[i].Port < allResults[j].Port
	})

	var finalResults []TargetResult
	for _, res := range allResults {
		if res.State == StateOpen || !e.opts.OnlyOpen {
			finalResults = append(finalResults, res)
			color := config.White
			switch res.State {
			case StateOpen:
				color = config.Green
			case StateClosed:
				color = config.Red
			}
			fmt.Printf("%s[+] %s:%-5d ─ %-8s%s (time=%.2fms | reason=%s)\n",
				color, res.IP, res.Port, res.State, config.Reset, res.LatencyMs, res.Reason)

			if e.scriptEngine != nil && res.State == StateOpen {
				scriptResults := e.scriptEngine.RunAll(res.IP, res.Port)
				for _, sr := range scriptResults {
					fmt.Printf("    |_ %s: %v\n", sr.ScriptName, sr.Output)
				}
			}
		}
	}

	return finalResults
}

func (e *Engine) dispatchScan(ip string, port int) TargetResult {
	res := e.runPrimaryScan(ip, port)

	isFiltered := res.State == StateFiltered || res.State == StateOpenFiltered
	if isFiltered && e.opts.SmartBypass {
		fmt.Printf("    %s[~] Port %s:%d is %s. Attempting bypass techniques...%s\n", config.Yellow, ip, port, res.State, config.Reset)
		return e.runBypassSequence(ip, port, res)
	}

	return res
}

func (e *Engine) runBypassSequence(ip string, port int, originalRes TargetResult) TargetResult {
	if !e.opts.UdpScan {
		ackRes := ScanAckPort(ip, port, e.opts, e.timeout)
		if ackRes.State == StateUnfiltered {
			finRes := ScanStealthPort(ip, port, ScanFin, e.opts, e.timeout)
			if finRes.State == StateClosed {
				finRes.Reason = "Bypass: ACK->unfiltered, FIN->closed"
				return finRes
			}
			return TargetResult{IP: ip, Port: port, State: StateOpen, Reason: "Bypass: ACK->unfiltered, FIN->filtered (implies OPEN)"}
		}
	}
	fragOpts := *e.opts
	fragOpts.Fragment = true
	fragRes := e.runScanWithOptions(ip, port, &fragOpts)
	if fragRes.State != StateFiltered && fragRes.State != StateOpenFiltered {
		fragRes.Reason = "Bypass: Fragmented scan succeeded"
		return fragRes
	}

	for _, srcPort := range []int{53, 80, 443} {
		spOpts := *e.opts
		spOpts.SourcePort = srcPort
		spRes := e.runScanWithOptions(ip, port, &spOpts)
		if spRes.State != StateFiltered && spRes.State != StateOpenFiltered {
			spRes.Reason = fmt.Sprintf("Bypass: Source port %d scan succeeded", srcPort)
			return spRes
		}
	}

	if !e.opts.UdpScan {
		winRes := ScanWindowPort(ip, port, e.opts, e.timeout)
		if winRes.State == StateOpen {
			winRes.Reason = "Bypass: Window scan detected open port"
			return winRes
		}
		if winRes.State == StateClosed {
			winRes.Reason = "Bypass: Window scan detected closed port"
			return winRes
		}
	}

	finalRes := originalRes
	finalRes.Reason += " (Bypass failed)"
	return finalRes
}

func (e *Engine) runPrimaryScan(ip string, port int) TargetResult {
	return e.runScanWithOptions(ip, port, e.opts)
}

func (e *Engine) runScanWithOptions(ip string, port int, opts *config.Options) TargetResult {
	if GlobalXsk != nil {
		if opts.UdpScan {
			return ScanXDPUDPPort(ip, port, opts, e.timeout)
		}
		isOtherRawScan := opts.AckScan || opts.WindowScan || opts.NullScan || opts.FinScan || opts.XmasScan
		if opts.SynScan || !isOtherRawScan {
			return ScanXDPPort(ip, port, opts, e.timeout)
		}
	}

	if opts.ZombieHost != "" {
		return ScanIdlePort(ip, port, opts.ZombieHost, opts, e.timeout)
	}
	if opts.AckScan {
		return ScanAckPort(ip, port, opts, e.timeout)
	}
	if opts.WindowScan {
		return ScanWindowPort(ip, port, opts, e.timeout)
	}
	if opts.UdpScan {
		return ScanUDPPort(ip, port, opts, e.timeout)
	}
	if opts.SynScan {
		return ScanSYNPort(ip, port, opts, e.timeout)
	}
	if opts.NullScan {
		return ScanStealthPort(ip, port, ScanNull, opts, e.timeout)
	}
	if opts.FinScan {
		return ScanStealthPort(ip, port, ScanFin, opts, e.timeout)
	}
	if opts.XmasScan {
		return ScanStealthPort(ip, port, ScanXmas, opts, e.timeout)
	}

	return ScanConnectPort(ip, port, opts, e.timeout)
}
