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
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", timeoutSec*1000), ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSec), ip)
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

	if ICMPPing(ip, timeout) {
		return true
	}

	probePorts := []int{80, 443, 22, 8080, 445, 3389, 21, 25, 3306, 8443}
	tcpTimeout := timeout / 2
	if tcpTimeout < 200*time.Millisecond {
		tcpTimeout = 200 * time.Millisecond
	}

	for _, port := range probePorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), tcpTimeout)
		if err == nil {
			conn.Close()
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
