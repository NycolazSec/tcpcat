//go:build linux

package scan

import (
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/NycolazSec/tcpcat/config"
)

// cpuTime is the process's user + system CPU time so far.
func cpuTime(tb testing.TB) time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		tb.Fatal(err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// benchProbe runs one complete raw-socket probe the way ScanSYNPort does:
// set the scanner up, send a SYN, wait for the reply through the shared
// receive loop, tear the scanner down. Nothing listens on the port, so the
// kernel answers every SYN with a RST.
func benchProbe(b *testing.B, opts *config.Options, port int) {
	s, err := newRawTCPScanner("127.0.0.1", port, opts, 2*time.Second, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	if err := s.Send(0x02); err != nil {
		b.Fatal(err)
	}
	pkt, err := s.Receive()
	if err != nil {
		b.Fatalf("port %d: %v", port, err)
	}
	if pkt.Flags&0x04 == 0 {
		b.Fatalf("port %d: flags %#x, want a RST", port, pkt.Flags)
	}
}

// BenchmarkRawProbe measures the per-probe cost of the raw-socket scan path
// (SYN, ACK, FIN/NULL/Xmas, idle all go through newRawTCPScanner), as wall
// time and as CPU time per probe. It needs root and sends to 127.0.0.1 only;
// run it in a throwaway network namespace so no other traffic is involved:
//
//	go test -run '^$' -bench RawProbe ./internal/scan/ \
//	  -exec 'sudo unshare -n sh -c "ip link set lo up && exec \"$@\"" sh'
func BenchmarkRawProbe(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("raw sockets need root")
	}
	opts := &config.Options{Interface: "lo"}
	var next atomic.Int64
	// Distinct ports give distinct reply keys. The scanner's own source port
	// is skipped: on loopback, a SYN to it is read back as its own reply.
	port := func() int {
		for {
			if p := int(next.Add(1)%60000) + 1024; p != 54321 {
				return p
			}
		}
	}

	b.Run("sequential", func(b *testing.B) {
		b.ReportAllocs()
		cpu0 := cpuTime(b)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchProbe(b, opts, port())
		}
		b.StopTimer()
		b.ReportMetric(float64(cpuTime(b)-cpu0)/float64(b.N)/1e3, "cpu-µs/probe")
	})
	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.SetParallelism(32) // many workers, as a real scan has
		cpu0 := cpuTime(b)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				benchProbe(b, opts, port())
			}
		})
		b.StopTimer()
		b.ReportMetric(float64(cpuTime(b)-cpu0)/float64(b.N)/1e3, "cpu-µs/probe")
	})
}
