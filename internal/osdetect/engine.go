// internal/osdetect/engine.go
package osdetect

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// GenerateSignature prend les octets bruts de la trame et les positions des en-têtes
// pour extraire l'empreinte numérique (Fingerprint) du système distant.
func GenerateSignature(frame []byte, ipStart int, tcpStart int) string {
	// 1. Extraction du TTL (Time To Live) - 8ème octet de l'en-tête IPv4
	if len(frame) < ipStart+9 {
		return "Unknown"
	}
	ttl := frame[ipStart+8]

	// 2. Extraction de la TCP Window Size - 14ème et 15ème octets du TCP
	if len(frame) < tcpStart+16 {
		return fmt.Sprintf("TTL:%d", ttl)
	}
	windowSize := binary.BigEndian.Uint16(frame[tcpStart+14 : tcpStart+16])

	// 3. Extraction de la taille de l'en-tête TCP pour isoler les Options
	dataOffset := (frame[tcpStart+12] >> 4) * 4
	if len(frame) < tcpStart+int(dataOffset) {
		return fmt.Sprintf("TTL:%d|W:%d", ttl, windowSize)
	}

	// 4. Parsing des Options TCP
	optionsBytes := frame[tcpStart+20 : tcpStart+int(dataOffset)]
	parsedOptions := parseTCPOptions(optionsBytes)

	// Estimation basique de l'OS basée sur le TTL initial (arrondi supérieur)
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

// parseTCPOptions décode la structure binaire complexe des options TCP
func parseTCPOptions(opt []byte) string {
	var sig []string
	i := 0
	for i < len(opt) {
		kind := opt[i]
		if kind == 0 { // End of Options (EoL)
			break
		}
		if kind == 1 { // NOP (No-Operation)
			sig = append(sig, "N")
			i++
			continue
		}

		// Pour toutes les autres options, le 2ème octet est la longueur
		if i+1 >= len(opt) {
			break
		}
		length := int(opt[i+1])
		if length < 2 { // Sécurité contre les boucles infinies sur trame malformée
			break
		}

		switch kind {
		case 2: // Maximum Segment Size (MSS)
			if i+4 <= len(opt) {
				mssVal := binary.BigEndian.Uint16(opt[i+2 : i+4])
				sig = append(sig, fmt.Sprintf("M%d", mssVal))
			}
		case 3: // Window Scale
			if i+3 <= len(opt) {
				wScale := opt[i+2]
				sig = append(sig, fmt.Sprintf("W%d", wScale))
			}
		case 4: // SACK Permitted
			sig = append(sig, "S")
		case 8: // Timestamps
			sig = append(sig, "T")
		default:
			sig = append(sig, fmt.Sprintf("U%d", kind)) // Unknown option
		}
		i += length
	}

	if len(sig) == 0 {
		return "None"
	}
	return strings.Join(sig, ",")
}