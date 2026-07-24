// internal/scan/engine.go
package scan

import (
	"fmt"
	"sync"
	"time"

	"tcpcat/config"
)

type ScanJob struct {
	IP   string
	Port int
}

type Engine struct {
	opts    *config.Options
	timeout time.Duration
}

func NewEngine(opts *config.Options) *Engine {
	timeoutSec := 2.0
	if opts != nil {
		switch opts.Timing {
		case 5:
			timeoutSec = 0.5
		case 4:
			timeoutSec = 1.0
		case 3:
			timeoutSec = 2.0
		case 2:
			timeoutSec = 3.0
		case 1:
			timeoutSec = 5.0
		}
	}

	return &Engine{
		opts:    opts,
		timeout: time.Duration(timeoutSec * float64(time.Second)),
	}
}

func (e *Engine) Execute(targets []string, ports []int) []TargetResult {
	totalJobs := len(targets) * len(ports)
	jobs := make(chan ScanJob, totalJobs)
	resultsChan := make(chan TargetResult, totalJobs)

	var wg sync.WaitGroup
	numWorkers := 100
	if e.opts != nil && e.opts.Workers > 0 {
		numWorkers = e.opts.Workers
	}
	if numWorkers > totalJobs {
		numWorkers = totalJobs
	}

	for w := 0; w < numWorkers; w++ {
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

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []TargetResult
	for res := range resultsChan {
		results = append(results, res)

		// 🛑 THE ABSOLUTE FILTER IS HERE:
		// If OnlyOpen is enabled, we silently skip anything that is not "OPEN", even in Verbose mode.
		if e.opts != nil && e.opts.OnlyOpen && res.State != StateOpen {
			continue
		}

		if res.State == StateOpen || (e.opts != nil && e.opts.Verbose) {
			color := config.Green
			if res.State == StateClosed {
				color = config.Red
			} else if res.State == StateFiltered || res.State == StateUnfiltered {
				color = config.Yellow
			}
			fmt.Printf("%s[+] %s:%-5d ─ %-8s%s (time=%.2fms | reason=%s)\n",
				color, res.IP, res.Port, res.State, config.Reset, res.LatencyMs, res.Reason)
		}
	}

	return results
}

// dispatchScan routes the task to the method enabled in the config
func (e *Engine) dispatchScan(ip string, port int) TargetResult {
	if e.opts == nil {
		return ScanConnectPort(ip, port, nil, e.timeout)
	}

	// 🚀 ABSOLUTE PRIORITY: AF_XDP Engine (Kernel Bypass)
	if e.opts.UseXDP {
		return ScanXDPPort(ip, port, e.opts, e.timeout)
	}

	// 1. ACK Scan (-sA)
	if e.opts.AckScan {
		return ScanAckPort(ip, port, e.opts, e.timeout)
	}

	// 2. Window Scan (-sW)
	if e.opts.WindowScan {
		return ScanWindowPort(ip, port, e.opts, e.timeout)
	}

	// 3. SYN Scan (-sS)
	if e.opts.SynScan {
		return ScanSYNPort(ip, port, e.opts, e.timeout)
	}

	// 4. UDP Scan (-sU)
	if e.opts.UdpScan {
		return ScanUDPPort(ip, port, e.opts, e.timeout)
	}

	// 5. Stealth Scans (-sN, -sF, -sX)
	if e.opts.NullScan {
		return ScanStealthPort(ip, port, ScanNull, e.opts, e.timeout)
	}
	if e.opts.FinScan {
		return ScanStealthPort(ip, port, ScanFin, e.opts, e.timeout)
	}
	if e.opts.XmasScan {
		return ScanStealthPort(ip, port, ScanXmas, e.opts, e.timeout)
	}

	// Fallback to TCP Connect (-sT) or default behavior
	return ScanConnectPort(ip, port, e.opts, e.timeout)
}