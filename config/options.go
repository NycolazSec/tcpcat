package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Red    = "\033[91m"
	Green  = "\033[92m"
	Yellow = "\033[93m"
	White  = "\033[97m"
	Cyan   = "\033[96m"
)

var Banner = fmt.Sprintf(`
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀   ⠀⠀%s⢤⣶⣄%s⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀%s⣀⣤⡾⠿⢿⡀%s⠀⠀⠀⠀%s⣠⣶⣿⣷%s
⠀⠀⠀⠀⠀⠀⠀⠀%s⢀⣴⣦⣴⣿⡋⠀⠀⠈⢳⡄%s⠀%s⢠⣾⣿⠁⠈⣿⡆%s      %s%stcpcat%s v1.0 %sby NycolazSec%s
⠀⠀⠀⠀⠀⠀⠀%s⣰⣿⣿⠿⠛⠉⠉⠁⠀⠀⠀⠹⡄%s%s⣿⣿⣿⠀⠀⢹⇇%s      %s%sModular Security & Network Engine%s
⠀⠀⠀⠀⠀%s⣠⣾⡿⠋⠁%s⠀⠀⠀⠀⠀⠀⠀⠀%s⣰⣏⢻⣿⣿⡆⠀⠸⣿%s
⠀⠀⠀%s⢀⣴⠟⠁%s⠀⠀⠀⠀⠀⠀⠀⠀⠀%s⢠⣾⣿⣿⣆⠹⣿⣷⠀⢘⣿%s
⠀⠀%s⢀⡾⠁%s⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀%s⢰⣿⣿⠋⠉⠛⠂⠹⠿⣲⣿⣿⣧%s
⠀%s⢠⠏%s⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀%s⢀⣤⣿⣿⣿⣷⣾⣿⡇⢀⠀⣼⣿⣿⣿⣧%s
%s⠰⠃%s⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀%s⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⡘⢿⣿⣿⣿%s
%s⠁%s⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀%s⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣷⡈⠿⢿⣿⡆%s
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀%s⠙⠛⠁⢙⠛⣿⣿⣿⣿⡟⠀⡿⠀⠀⢀⣿⡇%s
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀%s⠘⣶⣤⣉⣛⠻⠇⢠⣿⣾⣿⡄⢻⡇%s
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀%s⣿⣿⣿⣿⦦⣤⣾⣿⣿⣿⣿⣆%s
`,
	Red, Reset,
	Red, Reset, White, Reset,
	Red, Reset, White, Reset, White, Bold, Reset, Red, Reset,
	Red, Reset, White, Reset, White, Bold, Reset,
	Red, Reset, White, Reset,
	Red, Reset, White, Reset,
	Red, Reset, White, Reset,
	Red, Reset, White, Reset,
	Red, Reset, White, Reset,
	Red, Reset, White, Reset,
	White, Reset,
	White, Reset,
	White, Reset,
)

type Options struct {
	Target      string
	InputFile   string
	ExcludeHost string

	// Host Discovery
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

	SourcePort int
	TTL        int
	DataString string
	DataHex    string
	Fragment   bool

	Timing        int
	Workers       int
	Verbose       bool
	JsonOutput    string
	ScriptPath    string
	VulnersAPIKey string

	// Cloud-Aware
	AWSRegion string
	AWSTags   string
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
		"-T":               true,
		"-g":               true,
		"--ttl":            true,
		"--data-string":    true,
		"--data":           true,
		"--top-ports":      true,
		"-sI":              true,
		"--scripts":        true,
		"--vulners-apikey": true,
		"--aws-region":     true,
		"--aws-tags":       true,
		"-PU":              true,
	}

	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]
		if strings.HasPrefix(arg, "-") {
			flagsArgs = append(flagsArgs, arg)
			if valueFlags[arg] && i+1 < len(rawArgs) && !strings.HasPrefix(rawArgs[i+1], "-") {
				flagsArgs = append(flagsArgs, rawArgs[i+1])
				i++
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
	flag.BoolVar(&opts.Fragment, "frag", false, "Fragment packets to evade detection")

	flag.IntVar(&opts.Timing, "T", 3, "Set timing template (0-5, higher is faster)")
	flag.IntVar(&opts.Workers, "w", 100, "Number of parallel workers")
	flag.BoolVar(&opts.Verbose, "v", false, "Enable verbose output")
	flag.StringVar(&opts.JsonOutput, "j", "", "Export results to JSON file")
	flag.StringVar(&opts.ScriptPath, "scripts", "", "Path to directory containing Go scripts")
	flag.StringVar(&opts.VulnersAPIKey, "vulners-apikey", "", "Vulners.com API key for CVE lookup")

	flag.StringVar(&opts.AWSRegion, "aws-region", "", "AWS region for tag-based target discovery")
	flag.StringVar(&opts.AWSTags, "aws-tags", "", "Scan EC2 instances matching tags (e.g., 'Key=App,Value=Web')")

	flag.Usage = func() {
		fmt.Println(Banner)
		fmt.Printf("%sUsage:%s tcpcat <target> [options]\n\n", Bold, Reset)
		fmt.Println(Cyan + "TARGET & DISCOVERY SPECIFICATION:" + Reset)
		fmt.Printf("  %s<target>%s         Hostnames, IP addresses, CIDRs\n", Yellow, Reset)
		fmt.Printf("  %s-iL <file>%s       Input target list from file\n", Yellow, Reset)
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
		fmt.Printf("  %s--frag%s              Fragment packets to evade detection\n", Yellow, Reset)
		fmt.Println(Cyan + "\nTIMING & OUTPUT:" + Reset)
		fmt.Printf("  %s-T <0-5>%s        Set timing template\n", Yellow, Reset)
		fmt.Printf("  %s-w <workers>%s    Number of parallel workers\n", Yellow, Reset)
		fmt.Printf("  %s-v%s              Enable verbose output\n", Yellow, Reset)
		fmt.Printf("  %s-j <file>%s       Export results to JSON file\n", Yellow, Reset)
	}

	flag.Parse()

	if len(flag.Args()) > 0 {
		opts.Target = flag.Arg(0)
	}

	if opts.Target == "" && opts.InputFile == "" && opts.AWSTags == "" {
		flag.Usage()
		os.Exit(1)
	}

	return opts, nil
}
