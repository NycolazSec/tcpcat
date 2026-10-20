// Test fixture: tries more probes than a run is allowed and reports how
// many were answered (the engine must cap it at maxProbesPerRun).
package main

import "strconv"

func Dissect(ip string, port int) map[string]string {
	answered := 0
	for i := 0; i < 6; i++ {
		if Probe(nil) != nil {
			answered++
		}
	}
	return map[string]string{"answered": strconv.Itoa(answered), "target": ip + ":" + strconv.Itoa(port)}
}
