package scan

import (
	"fmt"
	"net"
	"time"

	"tcpcat/config"
)

func getZombieIPID(zombieIP string, zombiePort int, opts *config.Options, timeout time.Duration) (uint16, error) {
	scanner, err := newRawTCPScanner(zombieIP, zombiePort, opts, timeout, nil)
	if err != nil {
		return 0, err
	}
	defer scanner.Close()

	err = scanner.Send(0x10)
	if err != nil {
		return 0, fmt.Errorf("send to zombie failed: %v", err)
	}

	resp, err := scanner.Receive()
	if err != nil {
		return 0, fmt.Errorf("no response from zombie")
	}

	if resp.Flags&0x04 != 0 {
		return resp.IPID, nil
	}

	return 0, fmt.Errorf("zombie did not respond with RST")
}

func sendSpoofedSYN(targetIP string, targetPort int, zombieIP string, opts *config.Options, timeout time.Duration) error {
	zombieNetIP := net.ParseIP(zombieIP)
	if zombieNetIP == nil {
		return fmt.Errorf("invalid zombie IP address")
	}

	scanner, err := newRawTCPScanner(targetIP, targetPort, opts, timeout, zombieNetIP)
	if err != nil {
		return err
	}
	defer scanner.Close()

	return scanner.Send(0x02)
}

func ScanIdlePort(ip string, port int, zombieIP string, opts *config.Options, timeout time.Duration) TargetResult {
	t0 := time.Now()
	res := TargetResult{IP: ip, Port: port}

	if zombieIP == "" {
		res.State = StateFiltered
		res.Reason = "Zombie Host Not Configured (-sI)"
		return res
	}

	const zombieProbePort = 80

	initialID, err := getZombieIPID(zombieIP, zombieProbePort, opts, timeout)
	if err != nil {
		res.State = StateFiltered
		res.Reason = fmt.Sprintf("Zombie %s is not responding correctly: %v", zombieIP, err)
		return res
	}

	if err := sendSpoofedSYN(ip, port, zombieIP, opts, timeout); err != nil {
		res.State = StateFiltered
		res.Reason = fmt.Sprintf("Failed to send spoofed packet: %v", err)
		return res
	}

	time.Sleep(200 * time.Millisecond)

	finalID, err := getZombieIPID(zombieIP, zombieProbePort, opts, timeout)
	if err != nil {
		res.State = StateFiltered
		res.Reason = fmt.Sprintf("Zombie %s stopped responding: %v", zombieIP, err)
		return res
	}

	res.Latency = time.Since(t0)
	res.LatencyMs = float64(res.Latency.Microseconds()) / 1000.0

	if finalID == initialID+2 {
		res.State = StateOpen
		res.Reason = fmt.Sprintf("Idle scan (zombie %s): IPID increased by 2", zombieIP)
	} else {
		res.State = StateClosed
		res.Reason = fmt.Sprintf("Idle scan (zombie %s): IPID increased by 1", zombieIP)
	}
	return res
}
