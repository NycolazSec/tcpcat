//go:build linux

package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func mkQueueDirs(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if err := os.Mkdir(filepath.Join(dir, name), 0755); err != nil {
			t.Fatalf("Mkdir(%s): %v", name, err)
		}
	}
	return dir
}

func TestCountRXQueueDirs(t *testing.T) {
	tests := []struct {
		name string
		dirs []string
		want int
	}{
		{"single queue", []string{"rx-0", "tx-0"}, 1},
		{"multi queue", []string{"rx-0", "rx-1", "rx-2", "rx-3", "tx-0", "tx-1", "tx-2", "tx-3"}, 4},
		{"no rx dirs at all", []string{"tx-0"}, 1}, // falls back rather than reporting 0
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := mkQueueDirs(t, tt.dirs...)
			if got := countRXQueueDirs(dir); got != tt.want {
				t.Errorf("countRXQueueDirs() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCountRXQueueDirsMissingPath(t *testing.T) {
	if got := countRXQueueDirs(filepath.Join(t.TempDir(), "does-not-exist")); got != 1 {
		t.Errorf("countRXQueueDirs(missing path) = %d, want 1 (fallback)", got)
	}
}

func TestXDPSocketOptions(t *testing.T) {
	for _, queues := range []int{1, 2, 4, 8, 16, 32, 64} {
		o := xdpSocketOptions(queues)
		rings := map[string]int{
			"fill": o.FillRingNumDescs, "rx": o.RxRingNumDescs,
			"tx": o.TxRingNumDescs, "completion": o.CompletionRingNumDescs,
		}
		for name, n := range rings {
			// The kernel only accepts power-of-two rings.
			if n < 256 || n&(n-1) != 0 {
				t.Errorf("%d queue(s): %s ring = %d, want a power of two >= 256", queues, name, n)
			}
		}
		// Receiving can hold the fill ring plus the RX ring; transmit must
		// still have a full ring of frames of its own.
		if o.NumFrames < o.FillRingNumDescs+o.RxRingNumDescs+o.TxRingNumDescs {
			t.Errorf("%d queue(s): %d frames can't cover fill+rx+tx rings", queues, o.NumFrames)
		}
		if umem := queues * o.NumFrames * o.FrameSize; queues <= 32 && umem > 64<<20 {
			t.Errorf("%d queue(s): %d MiB of UMEM, want <= 64", queues, umem>>20)
		}
	}
	if got := xdpSocketOptions(1).RxRingNumDescs; got != 2048 {
		t.Errorf("single-queue RX ring = %d, want 2048", got)
	}
}
