package scan

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"tcpcat/config"
	"tcpcat/internal/connpool"
	"tcpcat/internal/scripting"
)

type ScanJob struct {
	IP   string
	Port int
}

type Progress struct {
	Completed int
	Total     int
	Open      int
	Closed    int
	Filtered  int
	Rate      float64
}

type ProgressFunc func(Progress)

type Engine struct {
	opts         *config.Options
	timeout      time.Duration
	scriptEngine *scripting.ScriptingEngine
	connPool     *connpool.Pool
}

func NewEngine(opts *config.Options) *Engine {
	timeoutSec := 3.0
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

	poolSize := 64
	if opts.ConnPoolSize > 0 {
		poolSize = opts.ConnPoolSize
	}
	pool := connpool.New(poolSize, 30*time.Second, timeout)

	return &Engine{
		opts:         opts,
		timeout:      timeout,
		scriptEngine: se,
		connPool:     pool,
	}
}

func (e *Engine) Execute(targets []string, ports []int) []TargetResult {
	return e.ExecuteWithProgress(targets, ports, nil)
}

func (e *Engine) ExecuteWithProgress(targets []string, ports []int, onProgress ProgressFunc) []TargetResult {
	workerCount := e.opts.MaxWorkers
	if workerCount < 1 {
		workerCount = 1
	}
	queueSize := workerCount * 2
	jobs := make(chan ScanJob, queueSize)
	resultsChan := make(chan TargetResult, queueSize)
	var allResults []TargetResult
	started := time.Now()

	var rateTicker *time.Ticker
	if e.opts.RateLimit > 0 && !e.opts.UnsafeNoLimits {
		interval := time.Second / time.Duration(e.opts.RateLimit)
		if interval < time.Nanosecond {
			interval = time.Nanosecond
		}
		rateTicker = time.NewTicker(interval)
		defer rateTicker.Stop()
	}

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if rateTicker != nil {
					<-rateTicker.C
				}
				res := e.dispatchScan(job.IP, job.Port, e.opts)
				resultsChan <- res
			}
		}()
	}

	go func() {
		batchSize := e.opts.BatchSize
		if batchSize < 1 {
			batchSize = 1000
		}
		batch := make([]ScanJob, 0, batchSize)
		flush := func() {
			for _, j := range batch {
				jobs <- j
			}
			batch = batch[:0]
		}
		for _, ip := range targets {
			for _, port := range ports {
				batch = append(batch, ScanJob{IP: ip, Port: port})
				if len(batch) >= batchSize {
					flush()
				}
			}
		}
		flush()
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	progress := Progress{Total: len(targets) * len(ports)}
	for res := range resultsChan {
		allResults = append(allResults, res)
		progress.Completed++
		switch res.State {
		case StateOpen:
			progress.Open++
		case StateClosed:
			progress.Closed++
		case StateFiltered, StateOpenFiltered:
			progress.Filtered++
		}
		if onProgress != nil {
			elapsed := time.Since(started).Seconds()
			if elapsed > 0 {
				progress.Rate = float64(progress.Completed) / elapsed
			}
			onProgress(progress)
		}
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
				config.Bold+color, res.IP, res.Port, res.State, config.Reset, res.LatencyMs, res.Reason)

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

func (e *Engine) dispatchScan(ip string, port int, opts *config.Options) TargetResult {
	res := e.runPrimaryScan(ip, port, opts)

	isFiltered := res.State == StateFiltered || res.State == StateOpenFiltered
	if isFiltered && opts.SmartBypass {
		fmt.Printf("    %s[~] Port %s:%d is %s. Attempting bypass techniques...%s\n", config.Yellow, ip, port, res.State, config.Reset)
		return e.runBypassSequence(ip, port, res, opts)
	}

	return res
}

func (e *Engine) runBypassSequence(ip string, port int, originalRes TargetResult, opts *config.Options) TargetResult {
	if !opts.UdpScan {
		ackRes := ScanAckPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
		if ackRes.State == StateUnfiltered {
			finRes := ScanStealthPort(ip, port, ScanFin, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
			if finRes.State == StateClosed {
				finRes.Reason = "Bypass: ACK->unfiltered, FIN->closed"
				return finRes
			}
			return TargetResult{IP: ip, Port: port, State: StateOpen, Reason: "Bypass: ACK->unfiltered, FIN->filtered (implies OPEN)"}
		}
	}
	fragOpts := *opts
	fragOpts.Fragment = true
	fragRes := e.runScanWithOptions(ip, port, &fragOpts)
	if fragRes.State != StateFiltered && fragRes.State != StateOpenFiltered {
		fragRes.Reason = "Bypass: Fragmented scan succeeded"
		return fragRes
	}

	for _, srcPort := range []int{53, 80, 443} {
		spOpts := *opts
		spOpts.SourcePort = srcPort
		spRes := e.runScanWithOptions(ip, port, &spOpts)
		if spRes.State != StateFiltered && spRes.State != StateOpenFiltered {
			spRes.Reason = fmt.Sprintf("Bypass: Source port %d scan succeeded", srcPort)
			return spRes
		}
	}

	if !opts.UdpScan {
		winRes := ScanWindowPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
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

func (e *Engine) runPrimaryScan(ip string, port int, opts *config.Options) TargetResult {
	return e.runScanWithOptions(ip, port, opts)
}

func (e *Engine) runScanWithOptions(ip string, port int, opts *config.Options) TargetResult {
	if GlobalXsk != nil {
		if opts.UdpScan {
			return ScanXDPUDPPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP)
		}
		isOtherRawScan := opts.AckScan || opts.WindowScan || opts.NullScan || opts.FinScan || opts.XmasScan
		if opts.SynScan || !isOtherRawScan {
			return ScanXDPPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP)
		}
	}

	if opts.ZombieHost != "" {
		return ScanIdlePort(ip, port, opts.ZombieHost, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
	}
	if opts.AckScan {
		return ScanAckPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
	}
	if opts.WindowScan {
		return ScanWindowPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
	}
	if opts.UdpScan {
		return ScanUDPPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
	}
	if opts.SynScan {
		return ScanSYNPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
	}
	if opts.NullScan {
		return ScanStealthPort(ip, port, ScanNull, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
	}
	if opts.FinScan {
		return ScanStealthPort(ip, port, ScanFin, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
	}
	if opts.XmasScan {
		return ScanStealthPort(ip, port, ScanXmas, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
	}

	return ScanConnectPooled(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.connPool)
}
