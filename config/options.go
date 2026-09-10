package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Red    = "\033[91m"
	Green  = "\033[92m" // Corrigé (était \033[97m = blanc)
	Yellow = "\033[93m" // Corrigé (était \033[97m = blanc)
	White  = "\033[97m"
	Cyan   = "\033[96m" // Corrigé (était \033[97m = blanc)
)

var Banner = fmt.Sprintf(`
%s  [eth0]====-%s._     _,-'""'-._%s       %s%s _____ ____ ____   ____    _  _____ %s
%s         (,-.'._,'(       |\'-/|%s      %s%s|_   _/ ___|  _ \ / ___|  / \|_   _|%s
%s             '-.-' \ )-'( , %s%so o%s%s)%s      %s%s  | || |   | |_) | |     / _ \ | |  %s
%s                   '-    \'_'"'-%s      %s%s  | || |___|  __/| |___ / ___ \| |  %s
%s    <--[SYN]--(sniffing)--[ACK]-->%s    %s%s  |_| \____|_|    \____/_/   \_\_|  %s
                                        %s%sModular Security & Network Engine%s
                                         %s[ eBPF / AF_XDP ] %sby NycolazSec%s
`,
	White, Red, Reset, Red, Bold, Reset,
	Red, Reset, Red, Bold, Reset,
	Red, Green, Bold, Reset, Red, Reset, Red, Bold, Reset,
	Red, Reset, Red, Bold, Reset,
	Yellow, Reset, Red, Bold, Reset,
	White, Bold, Reset,
	Yellow, White, Reset,
)

type Options struct {
	Target      string
	InputFile   string
	ExcludeHost string

	PingScan      bool
	SkipDiscovery bool
	UdpPing       int
	Traceroute    bool

	SynScan     bool
	ConnectScan bool
	AckScan     bool
	WindowScan  bool
	NullScan    bool
	FinScan     bool
	XmasScan    bool
	ZombieHost  string
	UdpScan     bool
	UseXDP      bool
	OnlyOpen    bool

	Ports    string
	TopPorts int

	ServiceDetect bool
	OsDetect      bool

	SourcePort   int
	TTL          int
	DataString   string
	DataHex      string
	Fragment     bool
	TTLJitter    bool
	SpoofedSrcIP net.IP
	DecoyIPs     string
	RelayServer  string

	Jitter         float64
	EvasionMode    string
	TTLMode        string
	WindowSize     int
	SourcePortMode string
	PoliteMode     bool
	ProbeTTL       int

	DeepInspect     bool
	PacketCapture   bool
	OSIVerbosity    int
	HexDump         bool
	TimingAnalysis  bool
	PayloadAnalysis bool
	ProtocolTracing bool

	Timing         int
	RateLimit      int
	AdaptiveRate   bool
	MaxRetries     int
	MaxWorkers     int
	BatchSize      int
	ConnPoolSize   int
	UnsafeNoLimits bool
	InsecureTLS    bool
	Verbose        bool
	JsonOutput     string
	ScopeFile      string
	Profile        string
	AuditLog       string
	BaselineFile   string
	ChangesOutput  string
	SARIFOutput    string
	ScriptPath     string
	VulnersAPIKey  string
	SmartBypass    bool

	AWSRegion string
	AWSTags   string

	Web     bool
	WebAddr string
	Update  bool
}

func ParseFlags() (*Options, error) {
	opts := &Options{}

	rawArgs := os.Args[1:]
	var flagsArgs []string
	var posArgs []string

	valueFlags := map[string]bool{
		"-p":               true,
		"-iL":              true,
		"-j":               true,
		"-w":               true,
		"--workers":        true,
		"-g":               true,
		"--ttl":            true,
		"--data-string":    true,
		"--data":           true,
		"--top-ports":      true,
		"--decoy":          true,
		"-sI":              true,
		"--scripts":        true,
		"-T":               true,
		"--vulners-apikey": true,
		"--rate":           true,
		"--aws-region":     true,
		"--aws-tags":       true,
		"--web-addr":       true,
		"--batch-size":     true,
		"--conn-pool":      true,
		"--relay-server":   true,
		"-PU":              true,
		"--scope-file":     true,
		"--profile":        true,
		"--audit-log":      true,
		"--baseline":       true,
		"--changes":        true,
		"--sarif":          true,

		"--jitter":           true,
		"--evasion":          true,
		"--ttl-mode":         true,
		"--window-size":      true,
		"--source-port-mode": true,
		"--probe-ttl":        true,

		"--osi-verbosity": true,
	}

	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]
		if strings.HasPrefix(arg, "-") {
			if arg == "--decoy" {
				flagsArgs = append(flagsArgs, arg)
				if i+1 < len(rawArgs) && !strings.HasPrefix(rawArgs[i+1], "-") {
					flagsArgs = append(flagsArgs, rawArgs[i+1])
					i++
				} else {
					flagsArgs = append(flagsArgs, "auto")
				}
				continue
			}
			flagsArgs = append(flagsArgs, arg)
			if valueFlags[arg] && i+1 < len(rawArgs) && !strings.HasPrefix(rawArgs[i+1], "-") {
				flagsArgs = append(flagsArgs, rawArgs[i+1])
				i++
			} else if valueFlags[arg] {

				fmt.Printf("%s[!] Avertissement : Le drapeau %s attend une valeur mais aucune n'a été fournie. Il sera ignoré.%s\n", Yellow, arg, Reset)
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	os.Args = append([]string{os.Args[0]}, append(flagsArgs, posArgs...)...)

	flag.StringVar(&opts.Ports, "p", "", "Port(s) to scan (e.g. 80 | 22,80,443 | 1-1000)")
	flag.StringVar(&opts.InputFile, "iL", "", "Input target list from file")
	flag.BoolVar(&opts.PingScan, "sn", false, "Ping Scan - disable port scan")
	flag.BoolVar(&opts.SkipDiscovery, "Pn", false, "Treat all hosts as online")
	flag.IntVar(&opts.UdpPing, "PU", 0, "UDP Ping discovery port")
	flag.BoolVar(&opts.Traceroute, "traceroute", false, "Trace hop path to target")

	flag.BoolVar(&opts.AckScan, "sA", false, "ACK Scan (Firewall mapping)")
	flag.BoolVar(&opts.WindowScan, "sW", false, "TCP Window Scan")
	flag.BoolVar(&opts.SynScan, "sS", false, "SYN Stealth Scan")
	flag.BoolVar(&opts.ConnectScan, "sT", false, "TCP Connect Scan")
	flag.BoolVar(&opts.NullScan, "sN", false, "TCP NULL Stealth Scan")
	flag.BoolVar(&opts.FinScan, "sF", false, "TCP FIN Stealth Scan")
	flag.BoolVar(&opts.XmasScan, "sX", false, "TCP Xmas Stealth Scan")
	flag.StringVar(&opts.ZombieHost, "sI", "", "Idle scan using <zombie_host>")
	flag.BoolVar(&opts.UdpScan, "sU", false, "UDP Port Scan")
	flag.IntVar(&opts.TopPorts, "top-ports", 0, "Scan <number> most common ports")
	flag.BoolVar(&opts.UseXDP, "ebpf", false, "Enable experimental AF_XDP/eBPF engine")
	flag.BoolVar(&opts.OnlyOpen, "open", false, "Show only open ports")

	flag.BoolVar(&opts.ServiceDetect, "sV", false, "Probe open ports for service/version info")
	flag.BoolVar(&opts.OsDetect, "O", false, "Enable OS detection")

	flag.IntVar(&opts.SourcePort, "g", 0, "Use given source port number")
	flag.IntVar(&opts.TTL, "ttl", 0, "Set IP time-to-live field")
	flag.StringVar(&opts.DataString, "data-string", "", "Append custom ASCII string to probes")
	flag.StringVar(&opts.DataHex, "data", "", "Append custom hex string to probes")
	flag.BoolVar(&opts.Fragment, "frag", false, "Fragment packets for authorized monitoring validation")
	flag.BoolVar(&opts.Fragment, "fragment", false, "Alias for --frag")
	flag.StringVar(&opts.RelayServer, "relay-server", "", "IP address of a relay server for IP-in-IP encapsulation")

	flag.Float64Var(&opts.Jitter, "jitter", 0.0, "Timing jitter (0.0-1.0: variation percentage)")
	flag.BoolVar(&opts.TTLJitter, "ttl-jitter", false, "Randomize TTL values with timing jitter")
	flag.StringVar(&opts.EvasionMode, "evasion", "off", "Packet variation mode: off, light, moderate, aggressive, stealthy")
	flag.StringVar(&opts.TTLMode, "ttl-mode", "fixed", "TTL mode: fixed, random, probe")
	flag.IntVar(&opts.WindowSize, "window-size", 0, "TCP window size (0=auto)")
	flag.StringVar(&opts.SourcePortMode, "source-port-mode", "fixed", "Source port mode: fixed, random")
	flag.BoolVar(&opts.PoliteMode, "timing", false, "Enable polite/paranoid timing (synonym for slower -T)")
	flag.IntVar(&opts.ProbeTTL, "probe-ttl", 64, "TTL value for probe packets")

	flag.BoolVar(&opts.DeepInspect, "deep-inspect", false, "ADVANCED: Surgical packet-level analysis (slower, detailed)")
	flag.BoolVar(&opts.PacketCapture, "capture", false, "Enable raw packet capture and storage")
	flag.IntVar(&opts.OSIVerbosity, "osi-verbosity", 4, "OSI layer detail level (1=L3 only, 7=full stack analysis)")
	flag.BoolVar(&opts.HexDump, "hex-dump", false, "Display packet hex dump + ASCII representation")
	flag.BoolVar(&opts.TimingAnalysis, "timing-analysis", false, "Show inter-packet timing and latency metrics")
	flag.BoolVar(&opts.PayloadAnalysis, "payload-analysis", false, "Dissect L7 application layer data and protocols")
	flag.BoolVar(&opts.ProtocolTracing, "protocol-trace", false, "Trace full protocol negotiation sequence (3-way handshake, etc)")

	flag.IntVar(&opts.Timing, "T", 3, "Set timing template (0-5, higher is faster)")
	flag.IntVar(&opts.MaxWorkers, "w", 0, "Number of parallel workers (default: auto-scaled to CPU cores × 32)")
	flag.IntVar(&opts.MaxWorkers, "workers", 0, "Number of parallel workers (alias for -w)")
	flag.IntVar(&opts.BatchSize, "batch-size", 1000, "Number of jobs dispatched per batch")
	flag.IntVar(&opts.ConnPoolSize, "conn-pool", 64, "Max idle TCP connections kept per address (for -sT scans)")
	flag.IntVar(&opts.RateLimit, "rate", 500, "Max packets per second for discovery and scans")
	flag.BoolVar(&opts.AdaptiveRate, "adaptive-rate", false, "Adjust send rate automatically from observed RTT/loss (AIMD) instead of a fixed --rate")
	flag.IntVar(&opts.MaxRetries, "max-retries", 2, "Resend a probe this many times before marking a port filtered (0 disables retries)")
	flag.BoolVar(&opts.UnsafeNoLimits, "unsafe-no-limits", false, "Disable concurrency limits (DANGEROUS: may cause OOM killer)")
	flag.BoolVar(&opts.Verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&opts.InsecureTLS, "k", false, "Allow insecure server connections (alias --insecure)")
	flag.StringVar(&opts.JsonOutput, "j", "", "Export results to JSON file")
	flag.StringVar(&opts.ScopeFile, "scope-file", "", "Authorized scope file (CIDRs, IPs, or domains)")
	flag.StringVar(&opts.Profile, "profile", "", "Scan profile: safe-production")
	flag.StringVar(&opts.AuditLog, "audit-log", "", "Append one audit record per scan to a JSONL file")
	flag.StringVar(&opts.BaselineFile, "baseline", "", "Prior JSON report used as a comparison baseline")
	flag.StringVar(&opts.ChangesOutput, "changes", "", "Write scan changes to a JSON file (requires --baseline)")
	flag.StringVar(&opts.SARIFOutput, "sarif", "", "Export security findings as SARIF 2.1.0")
	flag.StringVar(&opts.ScriptPath, "scripts", "", "Path to directory containing Go scripts")
	flag.StringVar(&opts.VulnersAPIKey, "vulners-apikey", "", "Vulners.com API key for CVE lookup")
	flag.BoolVar(&opts.SmartBypass, "smart-bypass", false, "Enable advanced monitoring validation on filtered ports")
	flag.BoolVar(&opts.SmartBypass, "spoof-agent", false, "Alias for --smart-bypass")
	flag.StringVar(&opts.DecoyIPs, "decoy", "", "Comma-separated list of decoy IPs (e.g., 1.1.1.1,2.2.2.2). Without a value, a default decoy pool is used.")

	flag.StringVar(&opts.AWSRegion, "aws-region", "", "AWS region for tag-based target discovery")
	flag.StringVar(&opts.AWSTags, "aws-tags", "", "Scan EC2 instances matching tags (e.g., 'Key=App,Value=Web')")
	flag.BoolVar(&opts.Web, "web", false, "Start the local web interface")
	flag.StringVar(&opts.WebAddr, "web-addr", "127.0.0.1:8080", "Web interface listen address")
	flag.BoolVar(&opts.Update, "update", false, "Check GitHub and update the tcpcat binary")

	flag.BoolVar(&opts.InsecureTLS, "insecure", false, "Allow insecure server connections")

	flag.Usage = func() {
		fmt.Println(Banner)
		fmt.Printf("%sUsage:%s tcpcat <target> [options]\n\n", Bold, Reset)
		fmt.Println(Cyan + "TARGET & DISCOVERY SPECIFICATION:" + Reset)
		fmt.Printf("  %s<target>%s         Hostnames, IP addresses, CIDRs\n", Yellow, Reset)
		fmt.Printf("  %s-iL <file>%s       Input target list from file\n", Yellow, Reset)
		fmt.Printf("  %s--scope-file <file>%s Restrict scans to authorized CIDRs, IPs, or domains\n", Yellow, Reset)
		fmt.Printf("  %s-sn%s             Ping Scan - disable port scan\n", Yellow, Reset)
		fmt.Println(Cyan + "\nCLOUD-AWARE TARGETING:" + Reset)
		fmt.Printf("  %s--aws-region <region>%s AWS region for tag-based discovery\n", Yellow, Reset)
		fmt.Printf("  %s--aws-tags <tags>%s   Scan EC2 instances matching tags (e.g., 'Key=App,Value=Web')\n", Yellow, Reset)
		fmt.Printf("  %s-Pn%s             Treat all hosts as online\n", Yellow, Reset)
		fmt.Printf("  %s-PU <port>%s      UDP Ping discovery port\n", Yellow, Reset)
		fmt.Println(Cyan + "\nPORT & SCAN SPECIFICATION:" + Reset)
		fmt.Printf("  %s-p <ports>%s      Ports to scan (e.g. 80,443 | 1-1024)\n", Yellow, Reset)
		fmt.Printf("  %s--top-ports <n>%s Scan n most common ports\n", Yellow, Reset)
		fmt.Printf("  %s-sS%s             TCP SYN Stealth Scan\n", Yellow, Reset)
		fmt.Printf("  %s-sT%s             TCP Connect Scan\n", Yellow, Reset)
		fmt.Printf("  %s-sA%s             TCP ACK Scan (Firewall rules detection)\n", Yellow, Reset)
		fmt.Printf("  %s-sW%s             TCP Window Scan\n", Yellow, Reset)
		fmt.Printf("  %s-sN%s             TCP NULL Stealth Scan\n", Yellow, Reset)
		fmt.Printf("  %s-sF%s             TCP FIN Stealth Scan\n", Yellow, Reset)
		fmt.Printf("  %s-sX%s             TCP Xmas Stealth Scan\n", Yellow, Reset)
		fmt.Printf("  %s-sI <zombie>%s   TCP Idle Scan (fully blind)\n", Yellow, Reset)
		fmt.Printf("  %s-sU%s             UDP Port Scan\n", Yellow, Reset)
		fmt.Printf("  %s--open%s          Show only open ports\n", Yellow, Reset)
		fmt.Printf("  %s--ebpf%s          Enable experimental AF_XDP/eBPF engine (Extreme Performance)\n", Yellow, Reset)
		fmt.Println(Cyan + "\nSERVICE & OS DETECTION:" + Reset)
		fmt.Printf("  %s-sV%s             Service & Version detection\n", Yellow, Reset)
		fmt.Printf("  %s--scripts <dir>%s Run scripts from directory for advanced detection\n", Yellow, Reset)
		fmt.Printf("  %s--vulners-apikey <key>%s Perform CVE lookup for detected services\n", Yellow, Reset)
		fmt.Printf("  %s-O%s              Enable OS detection\n", Yellow, Reset)
		fmt.Println(Cyan + "\nEVASION & OPTIONS:" + Reset)
		fmt.Printf("  %s-g <port>%s       Use specified source port\n", Yellow, Reset)
		fmt.Printf("  %s--ttl <val>%s     Set custom IP Time-To-Live\n", Yellow, Reset)
		fmt.Printf("  %s--data-string%s   Append custom ASCII payload\n", Yellow, Reset)
		fmt.Printf("  %s--data%s          Append custom HEX payload\n", Yellow, Reset)
		fmt.Printf("  %s--traceroute%s    Trace hop path to target\n", Yellow, Reset)
		fmt.Printf("  %s--relay-server <ip>%s Use a relay server for IP-in-IP encapsulation\n", Yellow, Reset)
		fmt.Printf("  %s--decoy <ips>%s   Comma-separated list of decoy IPs\n", Yellow, Reset)
		fmt.Printf("  %s--frag%s              Fragment packets for authorized monitoring validation\n", Yellow, Reset)
		fmt.Printf("  %s--smart-bypass%s  Enable advanced validation on filtered ports\n", Yellow, Reset)
		fmt.Println(Cyan + "\nADVANCED IDS/IPS VISIBILITY TESTING:" + Reset)
		fmt.Printf("  %s--evasion <mode>%s       Packet variation mode: off, light, moderate, aggressive, stealthy\n", Yellow, Reset)
		fmt.Printf("  %s--jitter <0.0-1.0>%s    Timing jitter for authorized monitoring validation\n", Yellow, Reset)
		fmt.Printf("  %s--ttl-mode <mode>%s     TTL mode: fixed, random, probe (default: fixed)\n", Yellow, Reset)
		fmt.Printf("  %s--probe-ttl <val>%s     Probe TTL value (default: 64)\n", Yellow, Reset)
		fmt.Printf("  %s--window-size <bytes>%s TCP window size manipulation (0=auto)\n", Yellow, Reset)
		fmt.Printf("  %s--source-port-mode <mode>%s Source port: fixed, random\n", Yellow, Reset)
		fmt.Println(Cyan + "\nDEEP PACKET INSPECTION & SURGICAL SCANNING:" + Reset)
		fmt.Printf("  %s--deep-inspect%s         ADVANCED: Surgical packet-level analysis\n", Yellow, Reset)
		fmt.Println("                             Shows L2-L7 OSI stack details, hex dumps, timing analysis")
		fmt.Printf("                             %sWARNING: Significantly slower, for network professionals only%s\n", Yellow, Reset)
		fmt.Printf("  %s--osi-verbosity <1-7>%s OSI detail level (1=L3, 4=default, 7=full protocol dissection)\n", Yellow, Reset)
		fmt.Printf("  %s--hex-dump%s             Display raw packet hex dump + ASCII representation\n", Yellow, Reset)
		fmt.Printf("  %s--capture%s              Enable raw packet capture and storage for offline analysis\n", Yellow, Reset)
		fmt.Printf("  %s--timing-analysis%s     Show inter-packet timing and latency metrics\n", Yellow, Reset)
		fmt.Printf("  %s--payload-analysis%s    Dissect L7 application layer data and protocols\n", Yellow, Reset)
		fmt.Printf("  %s--protocol-trace%s      Trace full protocol negotiation (3-way handshake, etc)\n", Yellow, Reset)
		fmt.Println(Cyan + "\nTIMING & OUTPUT:" + Reset)
		fmt.Printf("  %s-T <0-5>%s        Set timing template\n", Yellow, Reset)
		fmt.Printf("  %s--rate <pps>%s    Set max packets per second for discovery and scans\n", Yellow, Reset)
		fmt.Printf("  %s-w, --workers <n>%s Number of parallel workers (default: auto CPU×32)\n", Yellow, Reset)
		fmt.Printf("  %s--batch-size <n>%s  Jobs dispatched per batch (default: 1000)\n", Yellow, Reset)
		fmt.Printf("  %s--conn-pool <n>%s   Max idle TCP connections per address (default: 64)\n", Yellow, Reset)
		fmt.Printf("  %s-v%s              Enable verbose output\n", Yellow, Reset)
		fmt.Printf("  %s-j <file>%s       Export results to JSON file\n", Yellow, Reset)
		fmt.Printf("  %s--sarif <file>%s  Export findings as SARIF 2.1.0\n", Yellow, Reset)
		fmt.Printf("  %s--audit-log <file>%s Append an audit record in JSONL\n", Yellow, Reset)
		fmt.Printf("  %s--baseline <file>%s Compare with a prior JSON report\n", Yellow, Reset)
		fmt.Printf("  %s--changes <file>%s Write comparison results (requires --baseline)\n", Yellow, Reset)
		fmt.Printf("  %s--profile safe-production%s Conservative authorized-production profile\n", Yellow, Reset)
		fmt.Printf("  %s--update%s        Check the latest GitHub release and update this binary\n", Yellow, Reset)
		fmt.Printf("  %s-k, --insecure%s  Allow insecure SSL/TLS connections\n", Yellow, Reset)
		fmt.Printf("  %s--unsafe-no-limits%s Disable all concurrency limits (DANGEROUS)\n", Yellow, Reset)
		fmt.Printf("  %s--adaptive-rate%s Adjust send rate from observed RTT/loss instead of a fixed --rate\n", Yellow, Reset)
		fmt.Printf("  %s--max-retries <n>%s Resend a probe up to <n> times before marking filtered (default 2)\n", Yellow, Reset)
	}

	flag.Parse()

	if opts.Timing < 0 || opts.Timing > 5 {
		return nil, fmt.Errorf("timing must be between 0 and 5")
	}

	if opts.MaxWorkers <= 0 {
		cpuBased := runtime.NumCPU() * 32
		if cpuBased > 1024 {
			cpuBased = 1024
		}
		if cpuBased < 100 {
			cpuBased = 100
		}
		opts.MaxWorkers = cpuBased
	}

	if opts.TTLJitter {
		opts.TTLMode = "random"
		if opts.Jitter == 0 {
			opts.Jitter = 0.4
		}
	}
	if opts.DecoyIPs == "auto" {
		opts.DecoyIPs = "1.1.1.1,8.8.8.8,9.9.9.9"
	}
	if opts.RateLimit < 0 {
		return nil, fmt.Errorf("rate must not be negative")
	}
	if opts.TopPorts < 0 {
		return nil, fmt.Errorf("top-ports must not be negative")
	}
	if opts.TopPorts > 0 && strings.TrimSpace(opts.Ports) != "" {
		return nil, fmt.Errorf("ports and top-ports cannot be used together")
	}
	if opts.ChangesOutput != "" && opts.BaselineFile == "" {
		return nil, fmt.Errorf("changes requires a baseline file")
	}
	if opts.Profile != "" && opts.Profile != "safe-production" {
		return nil, fmt.Errorf("profile must be safe-production")
	}
	if opts.UdpPing < 0 || opts.UdpPing > 65535 {
		return nil, fmt.Errorf("UDP ping port must be 0 or between 1 and 65535")
	}
	if opts.SourcePort < 0 || opts.SourcePort > 65535 {
		return nil, fmt.Errorf("source port must be between 1 and 65535")
	}
	if opts.TTL < 0 || opts.TTL > 255 {
		return nil, fmt.Errorf("TTL must be between 1 and 255")
	}

	if opts.Jitter < 0 || opts.Jitter > 1.0 {
		return nil, fmt.Errorf("jitter must be between 0.0 and 1.0")
	}

	validEvasionModes := map[string]bool{
		"off": true, "light": true, "moderate": true, "aggressive": true, "stealthy": true,
	}
	if !validEvasionModes[opts.EvasionMode] {
		return nil, fmt.Errorf("evasion mode must be: off, light, moderate, aggressive, or stealthy")
	}

	validTTLModes := map[string]bool{
		"fixed": true, "random": true, "probe": true,
	}
	if !validTTLModes[opts.TTLMode] {
		return nil, fmt.Errorf("ttl-mode must be: fixed, random, or probe")
	}

	validSourcePortModes := map[string]bool{
		"fixed": true, "random": true,
	}
	if !validSourcePortModes[opts.SourcePortMode] {
		return nil, fmt.Errorf("source-port-mode must be: fixed or random")
	}

	if opts.ProbeTTL < 1 || opts.ProbeTTL > 255 {
		return nil, fmt.Errorf("probe-ttl must be between 1 and 255")
	}

	if opts.WindowSize < 0 || opts.WindowSize > 65535 {
		return nil, fmt.Errorf("window-size must be between 0 (auto) and 65535")
	}

	if opts.OSIVerbosity < 1 || opts.OSIVerbosity > 7 {
		return nil, fmt.Errorf("osi-verbosity must be between 1 (minimal) and 7 (full dissection)")
	}

	if opts.DeepInspect {

		opts.HexDump = true
		opts.TimingAnalysis = true
		opts.ProtocolTracing = true
		if opts.Verbose {
			fmt.Printf("%s[*] Deep Inspection Mode: Enabled surgical packet analysis%s\n", Cyan, Reset)
			fmt.Printf("    OSI Verbosity: %d (1=minimal, 7=maximum)%s\n", opts.OSIVerbosity, Reset)
		}
	}

	scanTypes := 0
	for _, enabled := range []bool{
		opts.SynScan, opts.ConnectScan, opts.AckScan, opts.WindowScan,
		opts.NullScan, opts.FinScan, opts.XmasScan, opts.UdpScan,
	} {
		if enabled {
			scanTypes++
		}
	}
	if scanTypes > 1 {
		return nil, fmt.Errorf("scan types are mutually exclusive")
	}

	if len(flag.Args()) > 0 {
		opts.Target = flag.Arg(0)
	}

	if !opts.Update && !opts.Web && opts.Target == "" && opts.InputFile == "" && opts.AWSTags == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := ValidateScanCompatibility(opts); err != nil {
		return nil, err
	}

	return opts, nil
}

func ApplyProfile(opts *Options) {
	if opts.Profile != "safe-production" {
		return
	}

	opts.Timing = 2
	opts.RateLimit = 300
	opts.UnsafeNoLimits = false
	opts.EvasionMode = "off"
	opts.Jitter = 0
	opts.TTLJitter = false
	opts.Fragment = false
	opts.DecoyIPs = ""
	opts.SmartBypass = false
	opts.ServiceDetect = true
}

func ValidateScanCompatibility(opts *Options) error {

	if opts.ConnectScan {

		incompatible := []string{}
		if opts.Fragment {
			incompatible = append(incompatible, "fragment")
		}
		if opts.TTLJitter {
			incompatible = append(incompatible, "ttl-jitter")
		}
		if opts.SmartBypass {
			incompatible = append(incompatible, "smart-bypass/spoof-agent")
		}
		if opts.DecoyIPs != "" {
			incompatible = append(incompatible, "decoy")
		}

		if len(incompatible) > 0 {
			fmt.Printf("%s[!] WARNING: TCP Connect scan (-sT) with incompatible options: %s%s\n",
				Yellow, strings.Join(incompatible, ", "), Reset)
			fmt.Printf("%s    These options require raw packet scans (-sS, -sA, etc.) to have effect.%s\n", Yellow, Reset)
		}
	}

	if opts.EvasionMode != "off" && opts.ConnectScan {
		fmt.Printf("%s[!] WARNING: Evasion mode with TCP Connect (-sT) has limited effect.%s\n", Yellow, Reset)
		fmt.Printf("%s    Consider using raw packet scans (-sS) for better evasion.%s\n", Yellow, Reset)
	}

	if opts.SmartBypass && opts.ConnectScan {
		fmt.Printf("%s[*] INFO: Smart bypass mode is bypassed for TCP Connect scans.%s\n", Cyan, Reset)
		opts.SmartBypass = false
	}

	if opts.Fragment && opts.UdpScan {
		fmt.Printf("%s[*] INFO: UDP fragmentation enabled (requires UDP-capable network stack).%s\n", Cyan, Reset)
	}

	return nil
}
