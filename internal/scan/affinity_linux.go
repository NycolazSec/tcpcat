//go:build linux

package scan

import (
	"log"

	"golang.org/x/sys/unix"
)

func setThreadAffinity(coreID int) {
	if coreID < 0 {
		return
	}

	var mask unix.CPUSet
	mask.Zero()
	mask.Set(coreID)
	if err := unix.SchedSetaffinity(0, &mask); err != nil {
		log.Printf("sched_setaffinity failed for core %d: %v", coreID, err)
	}
}
