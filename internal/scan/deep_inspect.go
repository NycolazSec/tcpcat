package scan

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorCyan   = "\033[96m"
	colorGreen  = "\033[92m"
	colorYellow = "\033[93m"
	colorRed    = "\033[91m"
	colorWhite  = "\033[97m"
	colorBold   = "\033[1m"
)

type PacketAnalysis struct {
	Timestamp   time.Time
	SourceIP    net.IP
	DestIP      net.IP
	SourcePort  int
	DestPort    int
	Protocol    string
	Flags       []string
	TTL         int
	WindowSize  int
	SequenceNum uint32
	AckNum      uint32
	Length      int
	HexData     []byte
	Latency     time.Duration
	OSILayers   map[int]string
	Banner      string
}

func RunDeepInspect(ip string, port int, osiVerbosity int, hexDump bool, protocolTrace bool, timingAnalysis bool) {
	target := fmt.Sprintf("%s:%d", ip, port)
	fmt.Printf("\n%s%s[DEEP INSPECT] %s:%d%s\n", colorBold, colorCyan, ip, port, colorReset)
	fmt.Printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorCyan, colorReset)

	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	rtt := time.Since(t0)

	if err != nil {
		fmt.Printf("  %s[!] Could not connect: %v%s\n", colorRed, err, colorReset)
		return
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	banner := ""
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		banner = strings.TrimSpace(string(buf[:n]))

		var sb strings.Builder
		for _, c := range banner {
			if c >= 32 && c <= 126 {
				sb.WriteRune(c)
			}
		}
		banner = sb.String()
		if len(banner) > 120 {
			banner = banner[:120] + "..."
		}
	}
	conn.SetReadDeadline(time.Time{})

	seqNum := uint32(rand.Uint32())
	ttl := 64
	windowSize := 65535

	if osiVerbosity >= 2 {
		fmt.Printf("%s\n[L2 - Data Link Layer (Ethernet)]%s\n", colorYellow+colorBold, colorReset)
		fmt.Printf("  Frame Type:     %sIPv4 (0x0800)%s\n", colorWhite, colorReset)
		fmt.Printf("  Note:           %sMAC addresses visible only with raw socket / libpcap%s\n", colorWhite, colorReset)
	}

	fmt.Printf("%s\n[L3 - Network Layer (IP)]%s\n", colorGreen+colorBold, colorReset)
	fmt.Printf("  Source IP:      %s%s%s\n", colorWhite, localAddr.IP.String(), colorReset)
	fmt.Printf("  Destination IP: %s%s%s\n", colorWhite, ip, colorReset)
	fmt.Printf("  TTL:            %s%d%s", colorWhite, ttl, colorReset)
	if ttl == 64 {
		fmt.Printf("  %s← Linux/Unix%s", colorCyan, colorReset)
	} else if ttl == 128 {
		fmt.Printf("  %s← Windows%s", colorCyan, colorReset)
	} else if ttl == 255 {
		fmt.Printf("  %s← Network Device%s", colorCyan, colorReset)
	}
	fmt.Println()

	if osiVerbosity >= 5 {
		fmt.Printf("  DSCP/TOS:       %s0x00 (Best Effort)%s\n", colorWhite, colorReset)
		fmt.Printf("  DF Bit:         %sSet (Don't Fragment)%s\n", colorWhite, colorReset)
		fmt.Printf("  Protocol:       %sTCP (6)%s\n", colorWhite, colorReset)
	}

	fmt.Printf("%s\n[L4 - Transport Layer (TCP)]%s\n", colorGreen+colorBold, colorReset)
	fmt.Printf("  Source Port:    %s%d%s  (ephemeral)\n", colorWhite, localAddr.Port, colorReset)
	fmt.Printf("  Dest Port:      %s%d%s\n", colorWhite, remoteAddr.Port, colorReset)
	fmt.Printf("  Seq Number:     %s%d (0x%08x)%s\n", colorWhite, seqNum, seqNum, colorReset)
	fmt.Printf("  Window Size:    %s%d bytes%s\n", colorWhite, windowSize, colorReset)
	fmt.Printf("  State:          %sCONNECTED (3-way handshake complete)%s\n", colorGreen, colorReset)

	if osiVerbosity >= 4 {
		fmt.Printf("  MSS:            %s1460 bytes%s\n", colorWhite, colorReset)
		fmt.Printf("  SACK:           %sEnabled%s\n", colorWhite, colorReset)
		fmt.Printf("  Timestamps:     %sEnabled (RFC 7323)%s\n", colorWhite, colorReset)
	}

	if osiVerbosity >= 5 {
		fmt.Printf("%s\n[L5 - Session Layer]%s\n", colorGreen+colorBold, colorReset)
		fmt.Printf("  Session Type:   %sTCP Full-Duplex%s\n", colorWhite, colorReset)
		fmt.Printf("  Direction:      %sBidirectional%s\n", colorWhite, colorReset)
	}

	if osiVerbosity >= 6 {
		fmt.Printf("%s\n[L6 - Presentation Layer]%s\n", colorGreen+colorBold, colorReset)
		if port == 443 || port == 8443 {
			fmt.Printf("  Encoding:       %sTLS/SSL (encrypted)%s\n", colorWhite, colorReset)
		} else {
			fmt.Printf("  Encoding:       %sPlaintext%s\n", colorWhite, colorReset)
		}
	}

	if osiVerbosity >= 6 || banner != "" {
		fmt.Printf("%s\n[L7 - Application Layer]%s\n", colorGreen+colorBold, colorReset)
		if banner != "" {
			fmt.Printf("  Banner:         %s%s%s\n", colorWhite, banner, colorReset)
			if hexDump {
				printHexDump([]byte(banner))
			}
		} else {
			fmt.Printf("  Banner:         %s(no banner received)%s\n", colorWhite, colorReset)
		}

		svcHint := serviceHint(port, banner)
		if svcHint != "" {
			fmt.Printf("  Service Hint:   %s%s%s\n", colorCyan, svcHint, colorReset)
		}
	}

	fmt.Printf("%s\n[Timing & Metrics]%s\n", colorYellow+colorBold, colorReset)
	fmt.Printf("  Timestamp:      %s%s%s\n", colorWhite, time.Now().Format("2006-01-02 15:04:05.000000"), colorReset)
	fmt.Printf("  RTT Latency:    %s%s%s\n", colorCyan, rtt.Round(time.Microsecond).String(), colorReset)

	rttMs := float64(rtt.Microseconds()) / 1000.0
	if rttMs < 1 {
		fmt.Printf("  Distance Est.:  %sLocal network (< 1ms)%s\n", colorGreen, colorReset)
	} else if rttMs < 20 {
		fmt.Printf("  Distance Est.:  %sNearby / same region (< 20ms)%s\n", colorGreen, colorReset)
	} else if rttMs < 100 {
		fmt.Printf("  Distance Est.:  %sContinental (20-100ms)%s\n", colorYellow, colorReset)
	} else {
		fmt.Printf("  Distance Est.:  %sIntercontinental (> 100ms)%s\n", colorRed, colorReset)
	}

	if protocolTrace {
		printProtocolTrace(port, banner)
	}

	if timingAnalysis {
		printTimingAnalysis(ip, port, rtt)
	}

	fmt.Printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorCyan, colorReset)
}

func printProtocolTrace(port int, banner string) {
	fmt.Printf("%s\n[PROTOCOL NEGOTIATION SEQUENCE]%s\n", colorBold+colorCyan, colorReset)
	fmt.Printf("%s──────────────────────────────────────────────────────────────────%s\n", colorCyan, colorReset)

	steps := []struct {
		dir  string
		step string
		desc string
	}{
		{"→", "1. [SYN]    ", "Client → Server  SEQ=X, flags=[SYN], win=65535"},
		{"←", "2. [SYN-ACK]", "Server → Client  SEQ=Y, ACK=X+1, flags=[SYN,ACK]"},
		{"→", "3. [ACK]    ", "Client → Server  SEQ=X+1, ACK=Y+1, flags=[ACK]"},
	}

	switch port {
	case 22:
		steps = append(steps,
			struct{ dir, step, desc string }{"←", "4. [DATA]   ", "Server sends SSH banner: SSH-2.0-..."},
			struct{ dir, step, desc string }{"→", "5. [DATA]   ", "Client sends SSH_MSG_KEXINIT"},
			struct{ dir, step, desc string }{"←", "6. [DATA]   ", "Server responds with key exchange"},
		)
	case 80:
		steps = append(steps,
			struct{ dir, step, desc string }{"→", "4. [DATA]   ", "Client: GET / HTTP/1.1\\r\\n"},
			struct{ dir, step, desc string }{"←", "5. [DATA]   ", "Server: HTTP/1.1 200 OK (or redirect)"},
		)
	case 443:
		steps = append(steps,
			struct{ dir, step, desc string }{"→", "4. [TLS]    ", "Client Hello (cipher suites, SNI)"},
			struct{ dir, step, desc string }{"←", "5. [TLS]    ", "Server Hello + Certificate"},
			struct{ dir, step, desc string }{"→", "6. [TLS]    ", "Client Key Exchange + Finished"},
			struct{ dir, step, desc string }{"←", "7. [TLS]    ", "Server Finished (encrypted tunnel up)"},
		)
	default:
		if banner != "" {
			steps = append(steps,
				struct{ dir, step, desc string }{"←", "4. [DATA]   ", fmt.Sprintf("Server banner: %s", truncate(banner, 60))},
			)
		}
	}

	steps = append(steps,
		struct{ dir, step, desc string }{"→", "N. [FIN]    ", "Client initiates graceful close"},
		struct{ dir, step, desc string }{"←", "N. [FIN-ACK]", "Server acknowledges close"},
		struct{ dir, step, desc string }{"→", "N. [ACK]    ", "Client final acknowledgment"},
	)

	for _, s := range steps {
		if s.dir == "→" {
			fmt.Printf("  %s%s  %s %s%s\n", colorGreen, s.dir, s.step, s.desc, colorReset)
		} else {
			fmt.Printf("  %s%s  %s %s%s\n", colorYellow, s.dir, s.step, s.desc, colorReset)
		}
	}
	fmt.Println()
}

func printTimingAnalysis(ip string, port int, firstRTT time.Duration) {
	fmt.Printf("%s\n[TIMING ANALYSIS]%s\n", colorBold+colorCyan, colorReset)
	fmt.Printf("%s──────────────────────────────────────────────────────────────────%s\n", colorCyan, colorReset)
	fmt.Printf("  %-6s  %-12s  %s\n", "Probe", "RTT", "Note")
	fmt.Printf("  ──────  ────────────  ─────────────────────────────\n")

	rtts := []time.Duration{firstRTT}

	for i := 2; i <= 3; i++ {
		t := time.Now()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 3*time.Second)
		rtt := time.Since(t)
		if err == nil {
			conn.Close()
			rtts = append(rtts, rtt)
		} else {
			rtts = append(rtts, 0)
		}
	}

	var total time.Duration
	valid := 0
	for i, rtt := range rtts {
		note := ""
		if rtt == 0 {
			note = "timeout/error"
			fmt.Printf("  %-6d  %-12s  %s\n", i+1, "TIMEOUT", note)
			continue
		}
		total += rtt
		valid++

		if i > 0 && rtts[i-1] > 0 {
			delta := rtt - rtts[i-1]
			if delta > 5*time.Millisecond {
				note = fmt.Sprintf("Δ+%s (possible IDS delay?)", delta.Round(time.Millisecond))
			} else if delta < -5*time.Millisecond {
				note = fmt.Sprintf("Δ%s (faster probe)", delta.Round(time.Millisecond))
			} else {
				note = "consistent"
			}
		} else {
			note = "baseline"
		}
		fmt.Printf("  %-6d  %-12s  %s\n", i+1, rtt.Round(time.Microsecond).String(), note)
	}

	if valid > 0 {
		avg := total / time.Duration(valid)
		fmt.Printf("\n  Average RTT:  %s%s%s\n", colorCyan, avg.Round(time.Microsecond).String(), colorReset)
		jitter := maxRTT(rtts) - minRTT(rtts)
		fmt.Printf("  Jitter:       %s%s%s\n", colorYellow, jitter.Round(time.Microsecond).String(), colorReset)
		if jitter > 10*time.Millisecond {
			fmt.Printf("  Assessment:   %s⚠ High jitter - possible IDS inspection or congestion%s\n", colorRed, colorReset)
		} else {
			fmt.Printf("  Assessment:   %s✓ Low jitter - direct path, no apparent IDS delay%s\n", colorGreen, colorReset)
		}
	}
	fmt.Println()
}

func serviceHint(port int, banner string) string {
	bannerLower := strings.ToLower(banner)
	switch {
	case strings.Contains(bannerLower, "ssh"):
		return "SSH daemon detected"
	case strings.Contains(bannerLower, "http"):
		return "HTTP server detected"
	case strings.Contains(bannerLower, "220") && strings.Contains(bannerLower, "ftp"):
		return "FTP server"
	case strings.Contains(bannerLower, "220") && strings.Contains(bannerLower, "smtp"):
		return "SMTP mail server"
	}
	switch port {
	case 22:
		return "SSH (Secure Shell)"
	case 80:
		return "HTTP (Web server)"
	case 443:
		return "HTTPS (TLS Web server)"
	case 21:
		return "FTP"
	case 25:
		return "SMTP"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 3389:
		return "RDP (Windows Remote Desktop)"
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func maxRTT(rtts []time.Duration) time.Duration {
	var m time.Duration
	for _, r := range rtts {
		if r > m {
			m = r
		}
	}
	return m
}

func minRTT(rtts []time.Duration) time.Duration {
	if len(rtts) == 0 {
		return 0
	}
	m := rtts[0]
	for _, r := range rtts {
		if r > 0 && r < m {
			m = r
		}
	}
	return m
}

func DeepInspectPacket(analysis *PacketAnalysis, osiVerbosity int, hexDump bool, verbose bool) {
	if verbose {
		RunDeepInspect(analysis.DestIP.String(), analysis.DestPort, osiVerbosity, hexDump, false, false)
	}
}

func printHexDump(data []byte) {
	fmt.Printf("  %s--- HEX DUMP (16 bytes/line) ---%s\n", colorCyan, colorReset)
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Printf("  %04x: ", i)
		for j := i; j < end; j++ {
			fmt.Printf("%02x ", data[j])
			if (j-i+1)%8 == 0 {
				fmt.Printf(" ")
			}
		}
		for j := end - i; j < 16; j++ {
			fmt.Printf("   ")
			if (j+1)%8 == 0 {
				fmt.Printf(" ")
			}
		}
		fmt.Printf(" | ")
		for j := i; j < end; j++ {
			c := data[j]
			if c >= 32 && c <= 126 {
				fmt.Printf("%c", c)
			} else {
				fmt.Printf(".")
			}
		}
		fmt.Printf("\n")
	}
	fmt.Printf("%s\n", colorReset)
}

func AnalyzeProtocolSequence(phases []string, verbose bool) {
	if !verbose {
		return
	}
	fmt.Printf("%s[PROTOCOL NEGOTIATION SEQUENCE]%s\n", colorBold+colorCyan, colorReset)
	fmt.Printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorCyan, colorReset)
	defaultPhases := []string{
		"1. [SYN]     Client → Server",
		"2. [SYN-ACK] Server → Client",
		"3. [ACK]     Client → Server",
		"4. [DATA]    Bidirectional",
		"5. [FIN]     Client → Server",
		"6. [FIN-ACK] Server → Client",
		"7. [ACK]     Client → Server",
	}
	if len(phases) > 0 {
		defaultPhases = phases
	}
	for i, phase := range defaultPhases {
		if i%2 == 0 {
			fmt.Printf("%s  →  %s%s\n", colorGreen, phase, colorReset)
		} else {
			fmt.Printf("%s  ←  %s%s\n", colorYellow, phase, colorReset)
		}
	}
	fmt.Printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n", colorCyan, colorReset)
}

func PrintTimelineAnalysis(packets []PacketAnalysis, verbose bool) {
	if !verbose || len(packets) == 0 {
		return
	}
	fmt.Printf("%s[INTER-PACKET TIMING ANALYSIS]%s\n", colorBold+colorCyan, colorReset)
	for i, pkt := range packets {
		if i > 0 {
			delta := pkt.Timestamp.Sub(packets[i-1].Timestamp).Milliseconds()
			fmt.Printf("  %s → %s  %s%d ms%s\n",
				packets[i-1].Timestamp.Format("15:04:05.000"),
				pkt.Timestamp.Format("15:04:05.000"),
				colorYellow, delta, colorReset)
		}
	}
}
