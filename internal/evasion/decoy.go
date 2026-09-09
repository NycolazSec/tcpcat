package evasion

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

type DecoyConfig struct {
	DecoyIPs []net.IP
	Enabled  bool
}

func ParseDecoys(decoyStr string) ([]net.IP, error) {
	if decoyStr == "" {
		return nil, nil
	}

	var ips []net.IP
	parts := strings.Split(decoyStr, ",")
	for _, p := range parts {
		ipStr := strings.TrimSpace(p)
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address in decoy list: '%s'", ipStr)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

type DecoySwarmEngine struct {
	RealIP          net.IP
	DecoyIPs        []net.IP
	Pattern         string
	SyncStrategy    string
	ReplyPort       uint16
	Bandwidth       int
	RandomGenerator *rand.Rand
}

type DecoyPacket struct {
	SourceIP net.IP
	ReplyIP  net.IP
	Port     uint16
	Timing   time.Time
}

func NewDecoySwarmEngine(realIP net.IP, decoyIPs []net.IP) *DecoySwarmEngine {
	return &DecoySwarmEngine{
		RealIP:          realIP,
		DecoyIPs:        decoyIPs,
		Pattern:         "random",
		SyncStrategy:    "staggered",
		ReplyPort:       0,
		Bandwidth:       0,
		RandomGenerator: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (dse *DecoySwarmEngine) GenerateDecoyPattern(totalPackets int, ports []uint16) []DecoyPacket {
	packets := make([]DecoyPacket, totalPackets)

	switch dse.Pattern {
	case "rotate":

		for i := 0; i < totalPackets; i++ {
			packets[i] = DecoyPacket{
				SourceIP: dse.DecoyIPs[i%len(dse.DecoyIPs)],
				ReplyIP:  dse.RealIP,
				Port:     ports[i%len(ports)],
				Timing:   time.Now().Add(time.Duration(i) * 10 * time.Millisecond),
			}
		}

	case "random":

		for i := 0; i < totalPackets; i++ {
			packets[i] = DecoyPacket{
				SourceIP: dse.DecoyIPs[dse.RandomGenerator.Intn(len(dse.DecoyIPs))],
				ReplyIP:  dse.RealIP,
				Port:     ports[i%len(ports)],
				Timing:   time.Now().Add(time.Duration(i) * 10 * time.Millisecond),
			}
		}

	case "staggered":

		for i := 0; i < totalPackets; i++ {
			decoyIdx := i % len(dse.DecoyIPs)
			offset := time.Duration(decoyIdx*50) * time.Millisecond
			packets[i] = DecoyPacket{
				SourceIP: dse.DecoyIPs[decoyIdx],
				ReplyIP:  dse.RealIP,
				Port:     ports[i%len(ports)],
				Timing:   time.Now().Add(time.Duration(i)*10*time.Millisecond + offset),
			}
		}

	case "burst":

		burstSize := totalPackets / len(dse.DecoyIPs)
		packetIdx := 0
		for d := 0; d < len(dse.DecoyIPs); d++ {
			for b := 0; b < burstSize && packetIdx < totalPackets; b++ {
				packets[packetIdx] = DecoyPacket{
					SourceIP: dse.DecoyIPs[d],
					ReplyIP:  dse.RealIP,
					Port:     ports[packetIdx%len(ports)],
					Timing:   time.Now().Add(time.Duration(packetIdx) * 5 * time.Millisecond),
				}
				packetIdx++
			}
		}
	}

	return packets
}

func (dse *DecoySwarmEngine) BandwidthDistribute(totalPPS int) map[string]int {
	distribution := make(map[string]int)
	ppsPerDecoy := totalPPS / len(dse.DecoyIPs)

	for _, ip := range dse.DecoyIPs {
		variance := ppsPerDecoy / 10
		if variance < 1 {
			variance = 1
		}
		jittered := ppsPerDecoy + dse.RandomGenerator.Intn(variance*2) - variance
		if jittered < 1 {
			jittered = 1
		}
		distribution[ip.String()] = jittered
	}

	return distribution
}

func (dse *DecoySwarmEngine) SelectDecoy() net.IP {
	if len(dse.DecoyIPs) == 0 {
		return dse.RealIP
	}
	return dse.DecoyIPs[dse.RandomGenerator.Intn(len(dse.DecoyIPs))]
}

func (dse *DecoySwarmEngine) IsSpoofedSource(ip net.IP) bool {
	for _, decoyIP := range dse.DecoyIPs {
		if decoyIP.Equal(ip) {
			return true
		}
	}
	return false
}

type DecoyStrategy int

const (
	StrategyDecoyRotate DecoyStrategy = iota
	StrategyDecoyRandom
	StrategyDecoyStaggered
	StrategyDecoyBurst
)
