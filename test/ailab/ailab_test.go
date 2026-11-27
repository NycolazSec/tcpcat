//go:build linux && ailab

package ailab

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	scannerNS = "tclab-scan"
	targetNS  = "tclab-target"
	scannerIP = "10.99.0.1"
	targetIP  = "10.99.0.2"
	ports     = "22,23,80,443,3306"
)

// Services of the lab target (see labsrv).
const (
	sshBanner     = "22|banner|SSH-2.0-OpenSSH_9.6p1 Debian-5"
	sshSlowBanner = "22|banner|SSH-2.0-OpenSSH_9.6p1 Debian-5|2s"
	sshSilent     = "22|silent"
	sshTarpit     = "22|tarpit||1s"
	web           = "80|http|nginx/1.24.0"
	tlsSilent     = "443|silent"
)

// allowList builds an nftables ruleset that drops everything but the
// established connections and the given ports, with extra rules first.
func allowList(allowed, extra string) string {
	return fmt.Sprintf(`table inet lab {
	set banned { type ipv4_addr; flags dynamic,timeout; }
	set rl { type ipv4_addr; flags dynamic,timeout; timeout 5s; }
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
		iif "lo" accept
		%s
		tcp dport { %s } accept
	}
}
`, extra, allowed)
}

// banAfter bans a source that opens more than three connections to the open
// ports within a minute, for the given time: what fail2ban, CrowdSec or an
// anti-DDoS do to a scanner. The closed ports answer with a reset, so the
// port scan itself only counts the open ones.
func banAfter(ban string) string {
	return allowList("22, 80", `ip saddr @banned drop
		tcp dport { 22, 80 } ct state new update @rl { ip saddr limit rate over 1/minute burst 3 packets } add @banned { ip saddr timeout `+ban+` } drop
		tcp dport != { 22, 80 } reject with tcp reset`)
}

type scenario struct {
	name     string
	services []string
	rules    string // nftables ruleset of the target; empty for none
	want     []string
	wantNot  []string
}

var scenarios = []scenario{
	{
		name:     "allow-list firewall",
		services: []string{sshBanner, web},
		rules:    allowList("22, 80", ""),
		want: []string{
			"lets only the open ports through and drops everything else silently",
			"nothing blocked your address",
			"OpenSSH",
		},
		wantNot: []string{"all 5 ports tested are filtered", "no longer do"},
	},
	{
		name:     "no firewall",
		services: []string{sshBanner, web},
		want:     []string{"nothing filters them, or a firewall refuses them with a reset"},
		wantNot:  []string{"drops everything else silently"},
	},
	{
		name:     "firewall that rejects out loud",
		services: []string{sshBanner, web},
		rules:    allowList("22, 80", "tcp dport 3306 reject with icmpx admin-prohibited"),
		want:     []string{"refuses some ports out loud (3306)"},
	},
	{
		name:     "open ports that never answer (SYN proxy, anti-DDoS)",
		services: []string{sshSilent, tlsSilent},
		rules:    allowList("22, 443", ""),
		want: []string{
			"its 2 open ports accept connections, but no service answered",
			"no banner even after 8.0 s, though SSH speaks first",
		},
	},
	{
		name:     "SSH that answers late",
		services: []string{sshSlowBanner, web},
		rules:    allowList("22, 80", ""),
		want: []string{
			"the service sent its banner after 2.",
			"UseDNS",
			"OpenSSH",
		},
		wantNot: []string{"no banner even after"},
	},
	{
		name:     "temporary limit after the scan",
		services: []string{sshBanner, web},
		rules:    banAfter("10s"),
		want: []string{
			"answered during the scan and no longer do",
			"answers again: a temporary limit",
		},
		wantNot: []string{"a ban, not a slowdown"},
	},
	{
		name:     "ban after the scan",
		services: []string{sshBanner, web},
		rules:    banAfter("10m"),
		want: []string{
			"answered during the scan and no longer do",
			"Still blocked after 15 s: a ban, not a slowdown",
		},
		wantNot: []string{"a temporary limit"},
	},
	{
		name:     "SSH tarpit",
		services: []string{sshTarpit},
		rules:    allowList("22", ""),
		want: []string{
			"trickles random lines instead of an SSH banner",
			"SSH tarpit is public, as expected",
		},
		wantNot: []string{"no banner even after"},
	},
	{
		name:     "nothing reachable (VPN only, port knocking)",
		services: []string{sshBanner, web},
		rules:    allowList("9", ""), // a port nothing listens on: everything scanned is dropped
		want: []string{
			"all 5 ports tested are filtered",
			"VPN or after a port-knocking sequence",
			"nothing answers, not even one slow connection",
		},
		wantNot: []string{"sensitive ports tested", "is not reachable"},
	},
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

func TestHardenedTargets(t *testing.T) {
	tcpcat, labsrv := os.Getenv("TCPCAT_BIN"), os.Getenv("LABSRV_BIN")
	if tcpcat == "" || labsrv == "" || os.Geteuid() != 0 {
		t.Skip("needs root, TCPCAT_BIN and LABSRV_BIN (see doc.go)")
	}
	for _, tool := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("needs %s", tool)
		}
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			setupNetwork(t)
			startServices(t, labsrv, sc.services)
			if sc.rules != "" {
				applyRules(t, sc.rules)
			}
			start := time.Now()
			out := scan(t, tcpcat)
			t.Logf("scan and analysis took %s", time.Since(start).Round(time.Second))
			// The report wraps its lines: compare with whitespace collapsed.
			flat := strings.Join(strings.Fields(out), " ")
			for _, w := range sc.want {
				if !strings.Contains(flat, w) {
					t.Errorf("the AI did not say %q", w)
				}
			}
			for _, w := range sc.wantNot {
				if strings.Contains(flat, w) {
					t.Errorf("the AI said %q", w)
				}
			}
			if t.Failed() {
				t.Logf("tcpcat's output:\n%s", out)
			}
		})
	}
}

func setupNetwork(t *testing.T) {
	t.Helper()
	teardown()
	t.Cleanup(teardown)
	for _, args := range [][]string{
		{"netns", "add", scannerNS},
		{"netns", "add", targetNS},
		{"link", "add", "tclab-s", "netns", scannerNS, "type", "veth", "peer", "name", "tclab-t", "netns", targetNS},
		{"-n", scannerNS, "addr", "add", scannerIP + "/24", "dev", "tclab-s"},
		{"-n", targetNS, "addr", "add", targetIP + "/24", "dev", "tclab-t"},
		{"-n", scannerNS, "link", "set", "lo", "up"},
		{"-n", targetNS, "link", "set", "lo", "up"},
		{"-n", scannerNS, "link", "set", "tclab-s", "up"},
		{"-n", targetNS, "link", "set", "tclab-t", "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
}

// teardown removes the namespaces, and with them their interfaces, rules
// and processes' network.
func teardown() {
	for _, ns := range []string{scannerNS, targetNS} {
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}
}

func startServices(t *testing.T, labsrv string, specs []string) {
	t.Helper()
	args := []string{"netns", "exec", targetNS, labsrv}
	for _, s := range specs {
		args = append(args, "-s", s)
	}
	cmd := exec.Command("ip", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	ready := make(chan bool, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- strings.TrimSpace(line) == "ready"
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("labsrv did not start")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("labsrv did not start in time")
	}
}

func applyRules(t *testing.T, rules string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.nft")
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ip", "netns", "exec", targetNS, "nft", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("nft: %v\n%s\n%s", err, out, rules)
	}
}

// scan runs tcpcat from the scanner's namespace, as an internet scan of the
// target, and returns what it printed without colors.
func scan(t *testing.T, tcpcat string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", scannerNS, tcpcat,
		"-sT", "-sV", "-Pn", "--ai-deep", "--ai-from", "internet", "--ai-lang", "en", "-p", ports, targetIP)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("tcpcat did not finish:\n%s", out)
	}
	if err != nil {
		// tcpcat exits non-zero when it found something to fix: not a failure here.
		t.Logf("tcpcat exited with %v", err)
	}
	return ansi.ReplaceAllString(string(out), "")
}
