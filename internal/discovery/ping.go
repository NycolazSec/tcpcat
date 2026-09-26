package discovery

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"time"
)

func ICMPPing(ip string, timeout time.Duration) bool {
	timeoutSec := int(timeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", timeoutSec*1000), ip) // #nosec G204 -- ip is the user's own scan target passed as an argv element (no shell is invoked), not attacker-controlled input
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSec), ip) // #nosec G204 -- ip is the user's own scan target passed as an argv element (no shell is invoked), not attacker-controlled input
	}

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return false
	}
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err == nil
	case <-time.After(timeout + 500*time.Millisecond):
		_ = cmd.Process.Kill()
		return false
	}
}

func PingHost(ip string, timeout time.Duration) bool {
	probePorts := []int{80, 443, 22, 8080, 445, 3389, 21, 25, 3306, 8443}
	tcpTimeout := timeout / 2
	if tcpTimeout < 200*time.Millisecond {
		tcpTimeout = 200 * time.Millisecond
	}

	// ICMP and the TCP probes race concurrently instead of ICMP-then-TCP:
	// a host that's actually down answers none of them, so running ICMP
	// first and only falling back to TCP on failure pays ICMPPing's own
	// worst case (timeout+500ms) *plus* a TCP probe's, back to back, for
	// every unresponsive host -- and every other target sharing the
	// caller's worker-pool slot waits behind it. Racing all of them bounds
	// the worst case to whichever single probe is slowest, not their sum.
	found := make(chan bool, 1+len(probePorts))
	go func() { found <- ICMPPing(ip, timeout) }()
	for _, port := range probePorts {
		go func(port int) {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), tcpTimeout)
			if err != nil {
				found <- false
				return
			}
			_ = conn.Close()
			found <- true
		}(port)
	}

	for i := 0; i < 1+len(probePorts); i++ {
		if <-found {
			return true
		}
	}
	return false
}

func DiscoverHost(ip string, udpPort int, timeout time.Duration) bool {
	if udpPort > 0 {
		return PingUDP(ip, udpPort, timeout)
	}
	return PingHost(ip, timeout)
}
