package evasion

import (
	"encoding/binary"
	"math/rand"
	"net"
	"time"
)

type FragmentationEngine struct {
	MTU               int
	OverlapStrategy   string
	DecoyFragments    int
	TimingGap         time.Duration
	ReassemblyTimeout time.Duration
	RandomGenerator   *rand.Rand
}

func NewFragmentationEngine(mtu int) *FragmentationEngine {
	return &FragmentationEngine{
		MTU:               mtu,
		OverlapStrategy:   "sequential",
		DecoyFragments:    0,
		TimingGap:         100 * time.Millisecond,
		ReassemblyTimeout: 30 * time.Second,
		RandomGenerator:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

type Fragment struct {
	Data          []byte
	Offset        int
	MoreFragments bool
	ID            uint16
}

func (fe *FragmentationEngine) FragmentPacket(
	payload []byte,
	dstIP net.IP,
	fragmentID uint16,
) []Fragment {
	fragments := []Fragment{}
	payloadSize := fe.MTU - 40

	if payloadSize <= 0 {
		payloadSize = 64
	}

	switch fe.OverlapStrategy {
	case "sequential":
		for offset := 0; offset < len(payload); offset += payloadSize {
			end := offset + payloadSize
			if end > len(payload) {
				end = len(payload)
			}

			frag := Fragment{
				Data:          payload[offset:end],
				Offset:        offset,
				MoreFragments: end < len(payload),
				ID:            fragmentID,
			}
			fragments = append(fragments, frag)
		}

	case "overlap":
		for offset := 0; offset < len(payload); offset += payloadSize / 2 {
			end := offset + payloadSize
			if end > len(payload) {
				end = len(payload)
			}

			frag := Fragment{
				Data:          payload[offset:end],
				Offset:        offset,
				MoreFragments: end < len(payload),
				ID:            fragmentID,
			}
			fragments = append(fragments, frag)
		}

	case "gaps":

		for offset := 0; offset < len(payload); offset += payloadSize {
			end := offset + payloadSize
			if end > len(payload) {
				end = len(payload)
			}

			frag := Fragment{
				Data:          payload[offset:end],
				Offset:        offset,
				MoreFragments: end < len(payload),
				ID:            fragmentID,
			}
			fragments = append(fragments, frag)
		}
	}

	if fe.DecoyFragments > 0 {
		for i := 0; i < fe.DecoyFragments; i++ {
			decoy := make([]byte, payloadSize)
			fe.RandomGenerator.Read(decoy)

			frag := Fragment{
				Data:          decoy,
				Offset:        len(payload) + (i * payloadSize),
				MoreFragments: i < fe.DecoyFragments-1,
				ID:            fragmentID + uint16(i+1),
			}
			fragments = append(fragments, frag)
		}
	}

	return fragments
}

func (fe *FragmentationEngine) IPv4FragmentHeader(
	packetID uint16,
	offsetBytes int,
	moreFragments bool,
	ttl int,
	payload []byte,
) []byte {
	header := make([]byte, 20)

	header[0] = 0x45

	header[1] = 0

	totalLen := 20 + len(payload)
	binary.BigEndian.PutUint16(header[2:4], uint16(totalLen))

	binary.BigEndian.PutUint16(header[4:6], packetID)

	flags := uint16(0)
	if moreFragments {
		flags |= 0x2000
	}
	offset := uint16(offsetBytes / 8)
	flagsOffset := flags | offset
	binary.BigEndian.PutUint16(header[6:8], flagsOffset)

	if ttl <= 0 {
		ttl = 64
	}
	header[8] = byte(ttl)

	header[9] = 6

	binary.BigEndian.PutUint16(header[10:12], 0)

	return append(header, payload...)
}

func (fe *FragmentationEngine) RandomizeFragmentOrder(
	fragments []Fragment,
) []Fragment {
	shuffled := make([]Fragment, len(fragments))
	copy(shuffled, fragments)

	for i := len(shuffled) - 1; i > 0; i-- {
		j := fe.RandomGenerator.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	return shuffled
}

func (fe *FragmentationEngine) CalculateFragmentationTime(
	fragmentCount int,
	strategy string,
) []time.Duration {
	timings := make([]time.Duration, fragmentCount)

	switch strategy {
	case "rapid":

		for i := 0; i < fragmentCount; i++ {
			timings[i] = time.Millisecond
		}

	case "spaced":

		for i := 0; i < fragmentCount; i++ {
			timings[i] = fe.ReassemblyTimeout + (time.Duration(i)*100)*time.Millisecond
		}

	case "random":

		for i := 0; i < fragmentCount; i++ {
			timings[i] = time.Duration(fe.RandomGenerator.Intn(5000)) * time.Millisecond
		}

	default:

		for i := 0; i < fragmentCount; i++ {
			timings[i] = fe.TimingGap
		}
	}

	return timings
}

type FragmentationStrategy int

const (
	StrategySequential FragmentationStrategy = iota
	StrategyOverlap
	StrategyGaps
	StrategyMixed
)
