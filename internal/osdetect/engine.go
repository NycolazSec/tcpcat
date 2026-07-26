package osdetect

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func GenerateSignature(frame []byte, ipStart int, tcpStart int) string {
	if len(frame) < ipStart+9 {
		return "Unknown"
	}
	ttl := frame[ipStart+8]

	if len(frame) < tcpStart+16 {
		return fmt.Sprintf("TTL:%d", ttl)
	}
	windowSize := binary.BigEndian.Uint16(frame[tcpStart+14 : tcpStart+16])

	dataOffset := (frame[tcpStart+12] >> 4) * 4
	if len(frame) < tcpStart+int(dataOffset) {
		return fmt.Sprintf("TTL:%d|W:%d", ttl, windowSize)
	}

	optionsBytes := frame[tcpStart+20 : tcpStart+int(dataOffset)]
	parsedOptions := parseTCPOptions(optionsBytes)

	guessedOS := "Unknown"
	if ttl <= 64 {
		guessedOS = "Linux/Unix"
	} else if ttl <= 128 {
		guessedOS = "Windows"
	} else if ttl <= 255 {
		guessedOS = "Cisco/Solaris"
	}

	return fmt.Sprintf("OS:%s (TTL:%d WIN:%d OPT:%s)", guessedOS, ttl, windowSize, parsedOptions)
}

func parseTCPOptions(opt []byte) string {
	var sig []string
	i := 0
	for i < len(opt) {
		kind := opt[i]
		if kind == 0 { // End of Options (EoL)
			break
		}
		if kind == 1 {
			sig = append(sig, "N")
			i++
			continue
		}

		if i+1 >= len(opt) {
			break
		}
		length := int(opt[i+1])
		if length < 2 { // Sécurité contre les boucles infinies sur trame malformée
			break
		}

		switch kind {
		case 2:
			if i+4 <= len(opt) {
				mssVal := binary.BigEndian.Uint16(opt[i+2 : i+4])
				sig = append(sig, fmt.Sprintf("M%d", mssVal))
			}
		case 3:
			if i+3 <= len(opt) {
				wScale := opt[i+2]
				sig = append(sig, fmt.Sprintf("W%d", wScale))
			}
		case 4:
			sig = append(sig, "S")
		case 8:
			sig = append(sig, "T")
		default:
			sig = append(sig, fmt.Sprintf("U%d", kind))
		}
		i += length
	}

	if len(sig) == 0 {
		return "None"
	}
	return strings.Join(sig, ",")
}
