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
