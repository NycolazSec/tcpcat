//go:build !linux

package inventory

import "errors"

// Collect is Linux-only: it reads the socket tables and process list from /proc.
func Collect() (Inventory, error) {
	return Inventory{}, errors.New("tcpcat inventory reads /proc and only runs on Linux; run it on the Linux host you want to explain")
}
