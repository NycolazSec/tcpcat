//go:build !linux

package passive

import (
	"context"
	"fmt"
)

// Watch is unavailable off Linux: eBPF tracepoints are a Linux kernel feature.
func Watch(ctx context.Context) ([]Flow, error) {
	return nil, fmt.Errorf("passive discovery (eBPF) is only supported on Linux")
}

// Supported mirrors the linux build's signature.
func Supported() error {
	return fmt.Errorf("passive discovery (eBPF) is only supported on Linux")
}
