package scan

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"tcpcat/config"
	"tcpcat/internal/connpool"
	"tcpcat/internal/evasion"
	"tcpcat/internal/scripting"
)

// usesRawTxPath reports whether this scan emits its probes as raw frames
// (raw socket or AF_XDP) rather than through the kernel's TCP stack. Only
// those paths retransmit and fan out decoys, so only they emit more than
// one packet per job -- a connect (-sT) or plain UDP-via-kernel job is one
// packet's worth of send from the pacer's point of view.
func usesRawTxPath(opts *config.Options) bool {
	if GlobalXsk != nil {
		return true
	}
	return opts.SynScan || opts.AckScan || opts.WindowScan ||
		opts.NullScan || opts.FinScan || opts.XmasScan || opts.UdpScan
}

// decoyCount is how many extra frames each job fans out for decoy cover,
// so the pacer can reserve their slots too instead of letting them escape
// the rate limit entirely (which the old per-job ticker did).
func decoyCount(opts *config.Options) int {
	if opts.DecoyIPs == "" {
		return 0
	}
	decoys, err := evasion.ParseDecoys(opts.DecoyIPs)
	if err != nil {
		return 0
	}
	return len(decoys)
}

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
	rtt          *RTTEstimator
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
		rtt:          NewRTTEstimator(),
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

	// Resume support: when --resume names a file, results already recorded
	// there are loaded as output and their target/port pairs are skipped,
	// while every new result is appended so a later interruption can resume
	// again. A failure to open it is fatal here -- silently ignoring it
	// would rescan everything and, worse, not record progress this time
	// either, defeating the flag the user explicitly asked for.
	var cp *checkpoint
	if e.opts.Resume != "" {
		var err error
		cp, err = openCheckpoint(e.opts.Resume)
		if err != nil {
			fmt.Printf("%s[!] Resume error: %v%s\n", config.Red, err, config.Reset)
			return nil
		}
		allResults = append(allResults, cp.priorResults()...)
		if len(allResults) > 0 {
			fmt.Printf("%s[*] Resuming: %d result(s) loaded from %s, skipping those already scanned.%s\n",
				config.White, len(allResults), e.opts.Resume, config.Reset)
		}
	}

	// One shared pacer for both the fixed and the adaptive case, built the
	// same way host discovery builds its own so --rate means one thing
	// across both phases. A fixed rate is just an AIMD limiter pinned with
	// min==max==rate so it never moves; the adaptive case lets it range
	// from a tenth of the requested rate up to 4x. Using the same
	// evenly-spaced pacer for both means the per-packet accounting below
	// applies uniformly.
	adaptive := e.opts.AdaptiveRate
	limiter := NewLimiterFromOptions(e.opts)

	// Packets emitted per job. On the raw-socket / AF_XDP paths a single
	// job is not a single packet: probeAttempts() retransmits, plus one
	// frame per decoy. Reserving that many pacer slots per job is what
	// keeps the real TX rate at the requested pps instead of a multiple of
	// it -- the gap that let a stress test flood the NIC's RX side. The
	// count is conservative (a port that replies on the first try still
	// reserves every retry's slot), which errs toward under-sending, the
	// safe direction when the goal is not to overwhelm the path.
	perJobPackets := 1
	if usesRawTxPath(e.opts) {
		perJobPackets = probeAttempts(e.opts) + decoyCount(e.opts)
	}

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if limiter != nil {
					limiter.WaitN(perJobPackets)
				}
				res := e.dispatchScan(job.IP, job.Port, e.opts)
				lost := res.State == StateFiltered || res.State == StateOpenFiltered
				if !lost && res.Latency > 0 {
					e.rtt.Sample(res.Latency)
				}
				if adaptive && limiter != nil {
					limiter.Report(lost)
				}
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

		numPorts := uint64(len(ports))
		total := uint64(len(targets)) * numPorts

		if e.opts.NoRandomize || numPorts == 0 {
			for _, ip := range targets {
				for _, port := range ports {
					if cp.isDone(ip, port) {
						continue
					}
					batch = append(batch, ScanJob{IP: ip, Port: port})
					if len(batch) >= batchSize {
						flush()
					}
				}
			}
		} else {
			// Dispatch in a randomized permutation of the flattened
			// target*port space (see permute.go) instead of strict list
			// order, so a long scan doesn't spend its first minutes
			// hammering the first few hosts back to back.
			perm := newJobPermutation(total)
			for {
				idx, ok := perm.next()
				if !ok {
					break
				}
				ip, port := targets[idx/numPorts], ports[idx%numPorts]
				if cp.isDone(ip, port) {
					continue
				}
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

	// Prior results (from a resumed checkpoint) already count as completed
	// against the full target*port total, so progress reflects the whole
	// scan rather than restarting at zero.
	progress := Progress{Total: len(targets) * len(ports), Completed: len(allResults)}
	for res := range resultsChan {
		allResults = append(allResults, res)
		cp.record(res)
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

	if err := cp.close(); err != nil {
		fmt.Printf("%s[!] Warning: could not flush resume checkpoint: %v%s\n", config.Yellow, err, config.Reset)
	}

	if adaptive && limiter != nil {
		fmt.Printf("%s[*] Adaptive timing: final rate %d pps, SRTT %v%s\n",
			config.White, limiter.CurrentRate(), e.rtt.SRTT(), config.Reset)
	}

	sort.Slice(allResults, func(i, j int) bool {
		if allResults[i].IP != allResults[j].IP {
			return allResults[i].IP < allResults[j].IP
		}
		return allResults[i].Port < allResults[j].Port
	})

	var finalResults []TargetResult
	var currentHost string
	hostOSShown := false
	hiddenClosed := 0

	// flushClosedSummary prints the pending per-host closed-port count (if
	// any) and resets it -- called on every host change and once more
	// after the loop, so the last host's count isn't dropped.
	flushClosedSummary := func() {
		if hiddenClosed > 0 {
			fmt.Printf("%s[~] %s ─ Not shown: %d closed port(s)%s\n",
				config.Bold+config.White, currentHost, hiddenClosed, config.Reset)
			hiddenClosed = 0
		}
	}

	for _, res := range allResults {
		if res.IP != currentHost {
			flushClosedSummary()
			currentHost = res.IP
			hostOSShown = false
		}
		if res.State != StateOpen && e.opts.OnlyOpen {
			continue
		}
		finalResults = append(finalResults, res)

		// CLOSED ports are hidden by default (--show-closed to opt back
		// in) and rolled into one per-host summary line instead -- a
		// scan of a full /24 with mostly-closed hosts used to bury the
		// open ports that actually matter under thousands of CLOSED
		// lines. This is purely a console-display choice: finalResults
		// (and so every export format) still includes every port
		// regardless, exactly as before.
		if res.State == StateClosed && !e.opts.ShowClosed {
			hiddenClosed++
			continue
		}

		// OS is fingerprinted independently per port (each open port's
		// own SYN/ACK is its own sample), but shown at most once per
		// host here -- repeating "guessed OS: X (Y%)" on every single
		// open port added nothing and made a multi-port host's output
		// harder to scan. The full per-port confidence is still in the
		// exported JSON (OS/OSConfidence on every matching result), just
		// not repeated on the console.
		if res.OS != "" && !hostOSShown {
			fmt.Printf("%s[i] %s ─ OS: %s (%.0f%% confidence)%s\n",
				config.Bold+config.Cyan, res.IP, res.OS, res.OSConfidence*100, config.Reset)
			hostOSShown = true
		}

		// [+] is reserved for OPEN; every other state (CLOSED when
		// --show-closed is given, FILTERED, OPEN|FILTERED, UNFILTERED)
		// gets its own [-]/[~] prefix instead, so a skimmed scroll of
		// the output can't mistake a filtered or closed port for an
		// open one.
		prefix, color := "[~]", config.White
		switch res.State {
		case StateOpen:
			prefix, color = "[+]", config.Green
		case StateClosed:
			prefix, color = "[-]", config.Red
		}
		fmt.Printf("%s%s %s:%-5d ─ %-8s%s (time=%.2fms | reason=%s)\n",
			config.Bold+color, prefix, res.IP, res.Port, res.State, config.Reset, res.LatencyMs, res.Reason)

		if e.scriptEngine != nil && res.State == StateOpen {
			scriptResults := e.scriptEngine.RunAll(res.IP, res.Port)
			for _, sr := range scriptResults {
				fmt.Printf("    |_ %s: %v\n", sr.ScriptName, sr.Output)
			}
		}
	}
	flushClosedSummary()

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
		ackRes := ScanAckPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.rtt)
		if ackRes.State == StateUnfiltered {
			finRes := ScanStealthPort(ip, port, ScanFin, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.rtt)
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
		winRes := ScanWindowPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.rtt)
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

// xdpEligible reports whether a target/port should go through the AF_XDP
// fast path, or fall through to the kernel's normal TCP/IP stack even with
// --ebpf active. Two cases must not take the XDP path:
//
//   - An explicit -sT (ConnectScan): the raw-scan gate below only excluded
//     the *other* raw scan types (ACK/Window/NULL/FIN/Xmas), so a plain
//     "-sT --ebpf" fell through its `!isOtherRawScan` check and got
//     silently promoted to a raw XDP SYN scan -- the opposite of what -sT
//     asks for (a real three-way handshake through the kernel), and
//     surprising for anyone who explicitly chose -sT expecting kernel
//     semantics.
//   - A loopback target (127.0.0.0/8, ::1): AF_XDP frames are always
//     addressed to the gateway's MAC on the physical interface
//     (localMAC/gatewayMAC in xdp.go), so a loopback destination becomes a
//     martian packet pushed out onto the wire instead of handled locally
//     by the kernel -- wasted at best.
func xdpEligible(ip string, opts *config.Options) bool {
	if opts.ConnectScan {
		return false
	}
	if parsed := net.ParseIP(ip); parsed != nil && parsed.IsLoopback() {
		return false
	}
	return true
}

func (e *Engine) runScanWithOptions(ip string, port int, opts *config.Options) TargetResult {
	if GlobalXsk != nil && xdpEligible(ip, opts) {
		if opts.UdpScan {
			return ScanXDPUDPPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, e.rtt)
		}
		isOtherRawScan := opts.AckScan || opts.WindowScan || opts.NullScan || opts.FinScan || opts.XmasScan
		if opts.SynScan || !isOtherRawScan {
			return ScanXDPPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, e.rtt)
		}
	}

	if opts.ZombieHost != "" {
		return ScanIdlePort(ip, port, opts.ZombieHost, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer))
	}
	if opts.AckScan {
		return ScanAckPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.rtt)
	}
	if opts.WindowScan {
		return ScanWindowPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.rtt)
	}
	if opts.UdpScan {
		return ScanUDPPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.rtt)
	}
	if opts.SynScan {
		return ScanSYNPort(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.rtt)
	}
	if opts.NullScan {
		return ScanStealthPort(ip, port, ScanNull, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.rtt)
	}
	if opts.FinScan {
		return ScanStealthPort(ip, port, ScanFin, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.rtt)
	}
	if opts.XmasScan {
		return ScanStealthPort(ip, port, ScanXmas, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.rtt)
	}

	return ScanConnectPooled(ip, port, opts, e.timeout, opts.SpoofedSrcIP, net.ParseIP(opts.RelayServer), e.connPool)
}
