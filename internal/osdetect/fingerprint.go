package osdetect

import "encoding/binary"

// TCPSignature is a structured version of the same fields GenerateSignature
// already extracts from a SYN/ACK, kept as typed data instead of a display
// string so it can be scored against a fingerprint database.
type TCPSignature struct {
	TTL      uint8
	Window   uint16
	MSS      uint16
	WScale   int8 // -1 when the window-scale option is absent
	SACKPerm bool
	TSPerm   bool
	NOPCount int
	OptOrder []byte // TCP option kind bytes, in the order they appeared
}

// Fingerprint is one known OS TCP/IP stack signature, weighted so that
// distinctive fields (option order, window scale) count for more than
// coarse ones (TTL bucket) when scoring a match.
type Fingerprint struct {
	Name string
	Sig  TCPSignature
}

// ttlBucket maps an observed TTL back to the initial TTL a stack most likely
// sent it with, since routers decrement TTL by one per hop and 64/128/255
// are the near-universal starting points.
func ttlBucket(ttl uint8) uint8 {
	switch {
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	default:
		return 255
	}
}

// KnownFingerprints is a small, hand-curated set of common TCP/IP stack
// signatures (initial TTL, default window, MSS, and TCP option order for a
// SYN/ACK). It intentionally covers the handful of stacks tcpcat is most
// likely to meet during authorized assessments rather than attempting to
// replicate nmap-os-db/p0f in full.
var KnownFingerprints = []Fingerprint{
	{
		Name: "Linux 3.x-5.x",
		Sig: TCPSignature{
			TTL: 64, Window: 29200, MSS: 1460, WScale: 7,
			SACKPerm: true, TSPerm: true,
			OptOrder: []byte{2, 4, 8, 1, 3}, // MSS, SACK-perm, Timestamps, NOP, WScale
		},
	},
	{
		Name: "Windows 10/11",
		Sig: TCPSignature{
			TTL: 128, Window: 65535, MSS: 1460, WScale: 8,
			SACKPerm: true, TSPerm: false,
			OptOrder: []byte{2, 1, 3, 1, 1, 4}, // MSS, NOP, WScale, NOP, NOP, SACK-perm
		},
	},
	{
		Name: "macOS / BSD",
		Sig: TCPSignature{
			TTL: 64, Window: 65535, MSS: 1460, WScale: 6,
			SACKPerm: true, TSPerm: true,
			OptOrder: []byte{2, 4, 8, 1, 3},
		},
	},
	{
		Name: "Cisco IOS / Solaris",
		Sig: TCPSignature{
			TTL: 255, Window: 4128, MSS: 1460, WScale: -1,
			SACKPerm: false, TSPerm: false,
			OptOrder: []byte{2},
		},
	},
}

// ParseTCPSignature extracts a structured TCPSignature from a raw frame at
// the same offsets GenerateSignature uses. It returns ok=false if the frame
// is too short to contain a full TCP header plus options.
func ParseTCPSignature(frame []byte, ipStart, tcpStart int) (TCPSignature, bool) {
	var sig TCPSignature
	sig.WScale = -1

	if len(frame) < ipStart+9 || len(frame) < tcpStart+20 {
		return sig, false
	}
	sig.TTL = frame[ipStart+8]
	sig.Window = binary.BigEndian.Uint16(frame[tcpStart+14 : tcpStart+16])

	dataOffset := int(frame[tcpStart+12]>>4) * 4
	if dataOffset < 20 || len(frame) < tcpStart+dataOffset {
		return sig, true // header parsed fine, just no options to read
	}

	opt := frame[tcpStart+20 : tcpStart+dataOffset]
	i := 0
	for i < len(opt) {
		kind := opt[i]
		sig.OptOrder = append(sig.OptOrder, kind)

		if kind == 0 { // End of Option List
			break
		}
		if kind == 1 { // NOP
			sig.NOPCount++
			i++
			continue
		}
		if i+1 >= len(opt) {
			break
		}
		length := int(opt[i+1])
		if length < 2 {
			break
		}

		switch kind {
		case 2: // MSS
			if i+4 <= len(opt) {
				sig.MSS = binary.BigEndian.Uint16(opt[i+2 : i+4])
			}
		case 3: // Window Scale
			if i+3 <= len(opt) {
				sig.WScale = int8(opt[i+2])
			}
		case 4: // SACK Permitted
			sig.SACKPerm = true
		case 8: // Timestamps
			sig.TSPerm = true
		}
		i += length
	}

	return sig, true
}

// optOrderSimilarity scores how closely two option orderings match as the
// fraction of the shorter list that appears, in the same order, as a
// subsequence of the longer one. 1.0 is an exact match, 0.0 shares nothing.
func optOrderSimilarity(a, b []byte) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	// Longest common subsequence, small inputs (<=~10 bytes) so the classic
	// O(n*m) DP table is effectively instant here.
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	lcs := dp[n][m]
	shorter := n
	if m < shorter {
		shorter = m
	}
	return float64(lcs) / float64(shorter)
}

// Match scores an observed signature against KnownFingerprints and returns
// the best guess along with a 0-1 confidence. An empty name and zero
// confidence mean no candidate scored above noise.
func Match(observed TCPSignature) (name string, confidence float64) {
	var best Fingerprint
	var bestScore float64

	for _, fp := range KnownFingerprints {
		score, total := 0.0, 0.0

		total += 3
		if ttlBucket(observed.TTL) == fp.Sig.TTL {
			score += 3
		}
		total += 2
		if observed.WScale == fp.Sig.WScale {
			score += 2
		}
		total += 1
		if observed.SACKPerm == fp.Sig.SACKPerm {
			score += 1
		}
		total += 1
		if observed.TSPerm == fp.Sig.TSPerm {
			score += 1
		}
		total += 1
		if observed.MSS != 0 && observed.MSS == fp.Sig.MSS {
			score += 1
		}
		total += 3
		score += 3 * optOrderSimilarity(fp.Sig.OptOrder, observed.OptOrder)

		norm := score / total
		if norm > bestScore {
			bestScore, best = norm, fp
		}
	}

	if bestScore < 0.4 { // too little agreement to call it a match
		return "", 0
	}
	return best.Name, bestScore
}

// ClassifyOS is the structured counterpart to GenerateSignature: it parses
// the same SYN/ACK bytes and returns tcpcat's best-guess OS name plus a
// confidence score from the fingerprint database, instead of a single
// TTL-bucket label.
func ClassifyOS(frame []byte, ipStart, tcpStart int) (name string, confidence float64) {
	sig, ok := ParseTCPSignature(frame, ipStart, tcpStart)
	if !ok {
		return "", 0
	}
	return Match(sig)
}
