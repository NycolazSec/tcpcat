package evasion

import (
	"math/rand"
)

type ProtocolEvasion struct {
	TCPWindowStrategy  string
	UDPChecksumInvalid bool
	ICMPEvasionMode    string
	RandomGenerator    *rand.Rand
}

func NewProtocolEvasion() *ProtocolEvasion {
	return &ProtocolEvasion{
		TCPWindowStrategy:  "normal",
		UDPChecksumInvalid: false,
		ICMPEvasionMode:    "none",
		RandomGenerator:    rand.New(rand.NewSource(int64(rand.Intn(100000)))),
	}
}

func (pe *ProtocolEvasion) TCPWindowEvasion() uint16 {
	switch pe.TCPWindowStrategy {
	case "zero-window":

		return 0

	case "invalid":

		return 65535

	case "fragmented":

		return 512

	case "random":

		return uint16(pe.RandomGenerator.Intn(65535) + 1)

	default:
		return 65535
	}
}

func (pe *ProtocolEvasion) UDPChecksumEvasion() uint16 {
	if pe.UDPChecksumInvalid {
		return 0xFFFF
	}
	return 0
}

func (pe *ProtocolEvasion) ICMPEvasionPayload() []byte {
	payload := make([]byte, 32)
	pe.RandomGenerator.Read(payload)
	return payload
}

func (pe *ProtocolEvasion) TCPFlagsEvasion(baseFlags uint8) uint8 {

	switch pe.RandomGenerator.Intn(3) {
	case 0:

		return baseFlags | 0x03
	case 1:

		return baseFlags | 0x04
	default:
		return baseFlags
	}
}

func (pe *ProtocolEvasion) TTLEvasion() int {

	return pe.RandomGenerator.Intn(128) + 1
}

func (pe *ProtocolEvasion) SequenceNumberEvasion() uint32 {

	return pe.RandomGenerator.Uint32()
}

func (pe *ProtocolEvasion) AcknowledgmentEvasion() uint32 {
	return pe.RandomGenerator.Uint32()
}

type ProtocolEvansionMode int

const (
	ModeNormal ProtocolEvansionMode = iota
	ModeAggressive
	ModeSneaky
	ModeRandom
)
