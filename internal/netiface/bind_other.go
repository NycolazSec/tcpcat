//go:build !linux

package netiface

import "fmt"

// BindToDevice is a Linux-only capability (SO_BINDTODEVICE); on other
// platforms the interface's own source IP (see Lookup, used for the
// dial/send source address) is the best available approximation.
func BindToDevice(fd int, ifaceName string) error {
	return fmt.Errorf("binding a socket to a specific interface is only supported on Linux")
}
