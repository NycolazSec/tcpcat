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
			fmt.Printf("%s[!] Erreur d'initialisation du moteur de scripts: %v%s\n", config.Red, err, config.Reset)
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
	for i := 0; i < e.opts.Workers; i++ {
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
	if GlobalXsk != nil {
		if e.opts.UdpScan {
			return ScanXDPUDPPort(ip, port, e.opts, e.timeout)
		}
		isOtherRawScan := e.opts.AckScan || e.opts.WindowScan || e.opts.NullScan || e.opts.FinScan || e.opts.XmasScan
		if e.opts.SynScan || !isOtherRawScan {
			return ScanXDPPort(ip, port, e.opts, e.timeout)
		}
	}

	if e.opts.ZombieHost != "" {
		return ScanIdlePort(ip, port, e.opts.ZombieHost, e.opts, e.timeout)
	}

	if e.opts.AckScan {
		return ScanAckPort(ip, port, e.opts, e.timeout)
	}
	if e.opts.WindowScan {
		return ScanWindowPort(ip, port, e.opts, e.timeout)
	}
	if e.opts.UdpScan {
		return ScanUDPPort(ip, port, e.opts, e.timeout)
	}
	if e.opts.SynScan {
		return ScanSYNPort(ip, port, e.opts, e.timeout)
	}
	if e.opts.NullScan {
		return ScanStealthPort(ip, port, ScanNull, e.opts, e.timeout)
	}
	if e.opts.FinScan {
		return ScanStealthPort(ip, port, ScanFin, e.opts, e.timeout)
	}
	if e.opts.XmasScan {
		return ScanStealthPort(ip, port, ScanXmas, e.opts, e.timeout)
	}

	return ScanConnectPort(ip, port, e.opts, e.timeout)
}
