//go:build linux

package passive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Watch attaches the passive tracepoint and collects flows until ctx is done.
// It needs CAP_BPF/CAP_PERFMON (root is sufficient) and a kernel with BPF ring
// buffers (>= 5.8). The returned flows are aggregated and sorted for display.
func Watch(ctx context.Context) ([]Flow, error) {
	// Loading a program and a ring buffer map both draw on the locked-memory
	// rlimit on older kernels; raise it rather than fail cryptically.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raising RLIMIT_MEMLOCK: %w", err)
	}

	spec := generateCollection()
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("loading eBPF program (verifier rejected it): %w", err)
		}
		return nil, fmt.Errorf("loading eBPF collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["tcpcat_flow_tp"]
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", prog, nil)
	if err != nil {
		return nil, fmt.Errorf("attaching sock:inet_sock_set_state tracepoint: %w", err)
	}
	defer func() { _ = tp.Close() }()

	rd, err := ringbuf.NewReader(coll.Maps["tcpcat_flows"])
	if err != nil {
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	defer func() { _ = rd.Close() }()

	// Unblock Read when the caller's context is cancelled (duration elapsed or
	// Ctrl-C): a closed reader makes an in-flight Read return os.ErrClosed.
	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	counts := make(map[key]int)
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				break
			}
			return nil, fmt.Errorf("reading ring buffer: %w", err)
		}
		ev, err := decodeEvent(rec.RawSample)
		if err != nil {
			continue // skip a malformed record rather than abort the whole run
		}
		if k, ok := classify(ev); ok {
			counts[k]++
		}
	}

	return aggregate(counts), nil
}

// aggregate turns the observed key->count map into a stable, readable ordering:
// listening sockets first, then connections, each sorted by local port.
func aggregate(counts map[key]int) []Flow {
	flows := make([]Flow, 0, len(counts))
	for k, n := range counts {
		flows = append(flows, k.toFlow(n))
	}
	sort.Slice(flows, func(i, j int) bool {
		// listen before connection
		if (flows[i].Kind == "listen") != (flows[j].Kind == "listen") {
			return flows[i].Kind == "listen"
		}
		if flows[i].LocalPort != flows[j].LocalPort {
			return flows[i].LocalPort < flows[j].LocalPort
		}
		if flows[i].RemoteIP != flows[j].RemoteIP {
			return flows[i].RemoteIP < flows[j].RemoteIP
		}
		return flows[i].RemotePort < flows[j].RemotePort
	})
	return flows
}

// Supported reports whether passive discovery can run on this process/kernel.
// It only checks the obvious precondition (effective root); the real check is
// Watch attaching, which surfaces a precise error.
func Supported() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("passive discovery needs root (CAP_BPF/CAP_PERFMON) to load the eBPF program")
	}
	return nil
}
