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

// Engine orchestre le scan multi-cibles / multi-ports.
type Engine struct {
	opts    *config.Options
	timeout time.Duration
}

func NewEngine(opts *config.Options) *Engine {
	// Ajustement dynamique du timeout selon le modèle -T (0-5)
	timeoutSec := 2.0
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

	return &Engine{
		opts:    opts,
		timeout: time.Duration(timeoutSec * float64(time.Second)),
	}
}

// Execute lance le pool de goroutines et retourne tous les résultats.
func (e *Engine) Execute(targets []string, ports []int) []TargetResult {
	totalJobs := len(targets) * len(ports)
	jobs := make(chan ScanJob, totalJobs)
	resultsChan := make(chan TargetResult, totalJobs)

	var wg sync.WaitGroup
	numWorkers := e.opts.Workers
	if numWorkers > totalJobs {
		numWorkers = totalJobs
	}
	if numWorkers <= 0 {
		numWorkers = 100
	}

	// Lancement du Worker Pool
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				res := ScanConnectPort(job.IP, job.Port, e.opts, e.timeout)
				resultsChan <- res
			}
		}()
	}

	// Envoi des tâches dans la file
	for _, ip := range targets {
		for _, port := range ports {
			jobs <- ScanJob{IP: ip, Port: port}
		}
	}
	close(jobs)

	// Attente de la fin des workers
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []TargetResult
	for res := range resultsChan {
		results = append(results, res)
		if res.State == StateOpen || e.opts.Verbose {
			color := config.Green
			if res.State == StateClosed {
				color = config.Red
			} else if res.State == StateFiltered {
				color = config.Yellow
			}
			fmt.Printf("%s[+] %s:%-5d ─ %-8s%s (time=%.2fms | reason=%s)\n",
				color, res.IP, res.Port, res.State, config.Reset, res.LatencyMs, res.Reason)
		}
	}

	return results
}