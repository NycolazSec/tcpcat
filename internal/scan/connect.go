package scan

import (
	"net"
	"strconv"
	"strings"
	"time"

	"tcpcat/config"
	"tcpcat/internal/connpool"
	"tcpcat/internal/evasion"
)

func ScanConnectPort(hostIP string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, relayIP net.IP) TargetResult {
	return ScanConnectPooled(hostIP, port, opts, timeout, spoofedSrcIP, relayIP, nil)
}

func ScanConnectPooled(hostIP string, port int, opts *config.Options, timeout time.Duration, spoofedSrcIP net.IP, relayIP net.IP, pool *connpool.Pool) TargetResult {
	res := TargetResult{
		IP:    hostIP,
		Port:  port,
		State: StateFiltered,
	}

	targetAddr := net.JoinHostPort(hostIP, strconv.Itoa(port))

	var conn net.Conn
	var err error
	t0 := time.Now()

	if relayIP != nil {
		return TargetResult{IP: hostIP, Port: port, State: StateFiltered, Reason: "Relay not supported for Connect Scan"}
	}

	useEvasion := opts != nil && (opts.SourcePort > 0 || opts.TTL > 0 || opts.DecoyIPs != "")

	if useEvasion {
		cfg, _ := evasion.NewConfig(opts.SourcePort, opts.TTL, opts.DataString, opts.DataHex, "", opts.DecoyIPs)
		dialer := evasion.NewCustomDialer(cfg, timeout)
		conn, err = dialer.Dial("tcp", targetAddr)
	} else if pool != nil {
		conn, err = pool.Get(targetAddr)
	} else {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = dialer.Dial("tcp", targetAddr)
	}

	latency := time.Since(t0)
	res.Latency = latency
	res.LatencyMs = float64(latency.Microseconds()) / 1000.0

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			res.State = StateFiltered
			res.Reason = "Connection Timeout"
		} else if strings.Contains(err.Error(), "refused") {
			res.State = StateClosed
			res.Reason = "Connection Refused"
		} else {
			res.State = StateFiltered
			res.Reason = err.Error()
		}
		return res
	}

	hasPayload := false
	if opts != nil {
		payload, _ := evasion.PreparePayload(opts.DataString, opts.DataHex)
		if len(payload) > 0 {
			hasPayload = true
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(payload)
		}
	}

	if pool != nil && !useEvasion && !hasPayload {
		pool.Put(targetAddr, conn)
	} else {
		conn.Close()
	}

	res.State = StateOpen
	res.Reason = "SYN-ACK Received"
	return res
}
