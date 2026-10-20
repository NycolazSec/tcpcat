// A tcpcat dissector: recognises Redis and reads its version.
//
// This is the only file to edit. Dissect runs once per open port; return
// the facts you found (shown in the scan output and in the JSON report
// under "scripts"), or nil when the port isn't yours. Probe is your one
// way to talk to the target: it sends bytes to the port being scanned --
// that port only -- and returns the answer.
//
// Build:  ./build.sh          ->  redis.wasm
// Run:    tcpcat -sT -p 6379 --scripts . <target>
package main

import "strings"

func Dissect(ip string, port int) map[string]string {
	// PING is read-only and answered by every Redis, even one that then
	// demands a password for anything else.
	reply := string(Probe([]byte("PING\r\n")))
	switch {
	case strings.HasPrefix(reply, "+PONG"):
		out := map[string]string{"service": "redis", "auth": "none"}
		// INFO is read-only too, and only answered without authentication.
		info := string(Probe([]byte("INFO server\r\n")))
		if i := strings.Index(info, "redis_version:"); i >= 0 {
			out["version"] = strings.TrimSpace(strings.SplitN(info[i+len("redis_version:"):], "\r\n", 2)[0])
		}
		return out
	case strings.HasPrefix(reply, "-NOAUTH"), strings.HasPrefix(reply, "-ERR") && strings.Contains(reply, "AUTH"):
		return map[string]string{"service": "redis", "auth": "required"}
	}
	return nil
}
