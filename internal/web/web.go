package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"tcpcat/config"
	"tcpcat/internal/ports"
	"tcpcat/internal/scan"
	"tcpcat/internal/service"
	"tcpcat/internal/target"
	"tcpcat/internal/vuln"
)

//go:embed index.html
var frontend embed.FS

type scanRequest struct {
	Target        string `json:"target"`
	Ports         string `json:"ports"`
	TopPorts      int    `json:"top_ports"`
	ScanType      string `json:"scan_type"`
	Workers       int    `json:"workers"`
	RateLimit     int    `json:"rate_limit"`
	Timing        int    `json:"timing"`
	SourcePort    int    `json:"source_port"`
	TTL           int    `json:"ttl"`
	DataString    string `json:"data_string"`
	DataHex       string `json:"data_hex"`
	SkipDiscovery bool   `json:"skip_discovery"`
	OnlyOpen      bool   `json:"only_open"`
	Fragment      bool   `json:"fragment"`
	SmartBypass   bool   `json:"smart_bypass"`
	Profile       string `json:"profile"`
	ScopeFile     string `json:"scope_file"`
	ServiceDetect bool   `json:"service_detect"`
}

type scanState struct {
	mu       sync.RWMutex
	running  bool
	started  time.Time
	finished time.Time
	progress scan.Progress
	results  []scan.TargetResult
	err      string
}

type server struct {
	state scanState
}

func Run(addr string) error {
	s := &server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/status", s.handleStatus)

	fmt.Printf("[*] Web interface available at http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := frontend.ReadFile("index.html")
	if err != nil {
		http.Error(w, "frontend unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var request scanRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if strings.TrimSpace(request.Target) == "" {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}
	if request.ScanType == "" {
		request.ScanType = "connect"
	}
	if request.Workers == 0 {
		request.Workers = 64
	}
	if request.RateLimit == 0 {
		request.RateLimit = 500
	}
	if request.Workers < 1 || request.Workers > 4096 {
		writeError(w, http.StatusBadRequest, "workers must be between 1 and 4096")
		return
	}
	if request.RateLimit < 0 {
		writeError(w, http.StatusBadRequest, "rate_limit must not be negative")
		return
	}
	if request.Profile != "" && request.Profile != "safe-production" {
		writeError(w, http.StatusBadRequest, "unsupported profile")
		return
	}

	options := &config.Options{
		ConnectScan:   true,
		MaxWorkers:    request.Workers,
		RateLimit:     request.RateLimit,
		Timing:        request.Timing,
		SourcePort:    request.SourcePort,
		TTL:           request.TTL,
		DataString:    request.DataString,
		DataHex:       request.DataHex,
		OnlyOpen:      request.OnlyOpen,
		SkipDiscovery: request.SkipDiscovery,
		Fragment:      request.Fragment,
		SmartBypass:   request.SmartBypass,
		Profile:       request.Profile,
		ScopeFile:     request.ScopeFile,
		ServiceDetect: request.ServiceDetect,
	}
	config.ApplyProfile(options)
	if err := applyScanType(options, request.ScanType); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	targets, err := target.ParseTargets([]string{request.Target})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if options.ScopeFile != "" {
		targets, err = target.FilterByScope(targets, options.ScopeFile)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(targets) == 0 {
			writeError(w, http.StatusForbidden, "no resolved targets are authorized by the scope file")
			return
		}
	}
	selectedPorts, err := ports.ParsePorts(request.Ports, request.TopPorts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.state.mu.Lock()
	if s.state.running {
		s.state.mu.Unlock()
		writeError(w, http.StatusConflict, "a scan is already running")
		return
	}
	s.state.running = true
	s.state.started = time.Now()
	s.state.finished = time.Time{}
	s.state.progress = scan.Progress{Total: len(targets) * len(selectedPorts)}
	s.state.results = nil
	s.state.err = ""
	s.state.mu.Unlock()

	go func() {
		results := scan.NewEngine(options).ExecuteWithProgress(targets, selectedPorts, func(progress scan.Progress) {
			s.state.mu.Lock()
			s.state.progress = progress
			s.state.mu.Unlock()
		})
		if options.ServiceDetect {
			enrichResults(results)
		}
		s.state.mu.Lock()
		s.state.results = results
		s.state.finished = time.Now()
		s.state.running = false
		s.state.mu.Unlock()
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{"status": "started"})
}

func enrichResults(results []scan.TargetResult) {
	offlineScanner, err := vuln.NewOfflineScanner()
	if err != nil {
		return
	}

	for i := range results {
		result := &results[i]
		if result.State != scan.StateOpen {
			continue
		}

		serviceInfo := service.DetectService(result.IP, result.Port, 2*time.Second, false)
		result.Service = serviceInfo.Name
		result.Version = serviceInfo.Version
		result.Banner = serviceInfo.Banner
		result.OS = serviceInfo.OS
		result.Assessment = scan.VulnerabilityAssessment{
			Status:     "not_assessed",
			Source:     offlineScanner.SourceName(),
			AssessedAt: time.Now().UTC(),
		}
		if result.Service == "unknown" || result.Version == "" {
			result.Assessment.Reason = "No reliable service version was detected."
			continue
		}

		vulnerabilities, err := offlineScanner.GetForSoftware(result.Service, result.Version)
		if err != nil {
			result.Assessment.Reason = "The offline vulnerability lookup failed."
			continue
		}
		sort.Slice(vulnerabilities, func(i, j int) bool { return vulnerabilities[i].CVSS > vulnerabilities[j].CVSS })
		result.Vulnerabilities = vuln.Enrich(vulnerabilities)
		if len(result.Vulnerabilities) == 0 {
			result.Assessment.Status = "no_match"
			result.Assessment.Reason = fmt.Sprintf("No matching vulnerabilities were found for %s %s.", result.Service, result.Version)
			continue
		}
		result.RiskSeverity = result.Vulnerabilities[0].Severity
		result.Assessment.Status = "matched"
		result.Assessment.Reason = fmt.Sprintf("Matched %s %s against the offline vulnerability database.", result.Service, result.Version)
	}
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	s.state.mu.RLock()
	response := struct {
		Running  bool                `json:"running"`
		Started  time.Time           `json:"started,omitempty"`
		Finished time.Time           `json:"finished,omitempty"`
		Results  []scan.TargetResult `json:"results"`
		Progress scan.Progress       `json:"progress"`
		Error    string              `json:"error,omitempty"`
	}{s.state.running, s.state.started, s.state.finished, s.state.results, s.state.progress, s.state.err}
	s.state.mu.RUnlock()
	writeJSON(w, http.StatusOK, response)
}

func applyScanType(options *config.Options, scanType string) error {
	options.ConnectScan = false
	switch strings.ToLower(scanType) {
	case "connect":
		options.ConnectScan = true
	case "syn":
		options.SynScan = true
	case "udp":
		options.UdpScan = true
	case "ack":
		options.AckScan = true
	case "window":
		options.WindowScan = true
	case "fin":
		options.FinScan = true
	case "null":
		options.NullScan = true
	case "xmas":
		options.XmasScan = true
	default:
		return fmt.Errorf("unsupported scan type %q", scanType)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}
