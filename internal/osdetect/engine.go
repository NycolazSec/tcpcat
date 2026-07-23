// internal/osdetect/engine.go
package osdetect

import "fmt"

type OSGuess struct {
	Family     string `json:"family"`
	Details    string `json:"details"`
	Confidence int    `json:"confidence_pct"`
}

// EstimateOSFromTTL estime la famille de système d'exploitation d'après le TTL reçu.
func EstimateOSFromTTL(ttl int) OSGuess {
	if ttl <= 0 {
		return OSGuess{Family: "Unknown", Details: "No TTL data available", Confidence: 0}
	}

	switch {
	case ttl <= 64:
		return OSGuess{
			Family:     "Linux / macOS / Unix",
			Details:    fmt.Sprintf("Observed TTL=%d (Initial TTL: 64)", ttl),
			Confidence: 85,
		}
	case ttl <= 128:
		return OSGuess{
			Family:     "Microsoft Windows",
			Details:    fmt.Sprintf("Observed TTL=%d (Initial TTL: 128)", ttl),
			Confidence: 90,
		}
	case ttl <= 255:
		return OSGuess{
			Family:     "Network Equipment / Cisco / Solaris",
			Details:    fmt.Sprintf("Observed TTL=%d (Initial TTL: 255)", ttl),
			Confidence: 75,
		}
	default:
		return OSGuess{
			Family:     "Unknown",
			Details:    fmt.Sprintf("Unusual TTL value: %d", ttl),
			Confidence: 10,
		}
	}
}