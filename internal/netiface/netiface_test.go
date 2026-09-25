package netiface

import "testing"

// TestDefaultInterfaceName only checks that a machine with any working
// route to the internet (true in CI and in practically every real
// environment) resolves to some non-empty interface name -- the exact
// name is environment-specific (eth0, en0, ...) so there's nothing more
// specific to assert here.
func TestDefaultInterfaceName(t *testing.T) {
	name, err := DefaultInterfaceName()
	if err != nil {
		t.Skipf("no route available in this environment: %v", err)
	}
	if name == "" {
		t.Error("DefaultInterfaceName() = \"\", want a non-empty interface name")
	}
}
