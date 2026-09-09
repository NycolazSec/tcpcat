//go:build !linux
// +build !linux

package scan

func setThreadAffinity(coreID int) {
	if coreID < 0 {
		return
	}

}
