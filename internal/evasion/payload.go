// internal/evasion/payload.go
package evasion

import (
	"encoding/hex"
	"fmt"
)

// PreparePayload convertit une chaîne ASCII ou hexadécimale en bytes bruts.
func PreparePayload(dataStr string, dataHex string) ([]byte, error) {
	if dataHex != "" {
		b, err := hex.DecodeString(dataHex)
		if err != nil {
			return nil, fmt.Errorf("invalid hexadecimal format: %v", err)
		}
		return b, nil
	}
	if dataStr != "" {
		return []byte(dataStr), nil
	}
	return nil, nil
}