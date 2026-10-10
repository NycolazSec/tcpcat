package evidence

import (
	"bufio"
	"net"
	"strconv"
	"time"
)

const (
	OutcomeReproduced = "reproduced" // still open, same service
	OutcomeChanged    = "changed"    // still open, different banner
	OutcomeFixed      = "fixed"      // no longer reachable
)

type Outcome struct {
	Finding Finding `json:"finding"`
	Result  string  `json:"result"`
	Detail  string  `json:"detail"`
}

// Probe reports whether ip:port accepts a TCP connection and, if so, the
// banner it volunteers within a short read window (empty if none).
type Probe func(ip string, port int) (open bool, banner string, err error)

// TCPProbe is the production probe: a plain TCP connect plus a brief read.
func TCPProbe(timeout time.Duration) Probe {
	return func(ip string, port int) (bool, string, error) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
		if err != nil {
			return false, "", nil // refused or filtered: not reachable
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		line, _ := bufio.NewReader(conn).ReadString('\n')
		return true, line, nil
	}
}

// Replay re-probes each finding. A banner is compared only when one was
// recorded and the service volunteers one again (an HTTP server, for
// instance, sends nothing until asked, so it can't be compared this way).
func Replay(findings []Finding, probe Probe) []Outcome {
	outcomes := make([]Outcome, 0, len(findings))
	for _, f := range findings {
		open, banner, err := probe(f.IP, f.Port)
		o := Outcome{Finding: f}
		switch {
		case err != nil:
			o.Result, o.Detail = OutcomeReproduced, "probe error, treated as not fixed: "+err.Error()
		case !open:
			o.Result, o.Detail = OutcomeFixed, "port no longer accepts connections"
		case f.BannerSHA256 != "" && banner != "" && !bannerMatches(f, banner):
			o.Result, o.Detail = OutcomeChanged, "port still open, but the service answers differently"
		default:
			o.Result, o.Detail = OutcomeReproduced, "port still accepts connections"
		}
		outcomes = append(outcomes, o)
	}
	return outcomes
}

// bannerMatches compares the first line the service sent now with the one
// recorded (service detection keeps the first line, sometimes trimmed).
func bannerMatches(f Finding, banner string) bool {
	if BannerHash(banner) == f.BannerSHA256 {
		return true
	}
	trimmed := trimLine(banner)
	return trimmed != "" && (BannerHash(trimmed) == f.BannerSHA256 || trimmed == trimLine(f.Banner))
}

func trimLine(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
