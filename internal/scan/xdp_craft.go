package scan

import (
	"encoding/binary"
	"net"
)

func constructSYNFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	frame := make([]byte, 54)

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ipStart := 14
	frame[ipStart] = 0x45
	frame[ipStart+1] = 0x00
	binary.BigEndian.PutUint16(frame[ipStart+2:ipStart+4], 40)
	binary.BigEndian.PutUint16(frame[ipStart+4:ipStart+6], 0x1234)
	binary.BigEndian.PutUint16(frame[ipStart+6:ipStart+8], 0x4000)
	frame[ipStart+8] = 64
	frame[ipStart+9] = 6
	binary.BigEndian.PutUint16(frame[ipStart+10:ipStart+12], 0)
	copy(frame[ipStart+12:ipStart+16], srcIP.To4())
	copy(frame[ipStart+16:ipStart+20], dstIP.To4())

	ipChecksum := xdpChecksum(frame[ipStart : ipStart+20])
	binary.BigEndian.PutUint16(frame[ipStart+10:ipStart+12], ipChecksum)

	tcpStart := 34
	binary.BigEndian.PutUint16(frame[tcpStart:tcpStart+2], srcPort)
	binary.BigEndian.PutUint16(frame[tcpStart+2:tcpStart+4], dstPort)
	binary.BigEndian.PutUint32(frame[tcpStart+4:tcpStart+8], 0x11223344)
	binary.BigEndian.PutUint32(frame[tcpStart+8:tcpStart+12], 0)
	frame[tcpStart+12] = 0x50
	frame[tcpStart+13] = 0x02
	binary.BigEndian.PutUint16(frame[tcpStart+14:tcpStart+16], 64240)
	binary.BigEndian.PutUint16(frame[tcpStart+16:tcpStart+18], 0)
	binary.BigEndian.PutUint16(frame[tcpStart+18:tcpStart+20], 0)

	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6
	binary.BigEndian.PutUint16(pseudoHeader[10:12], 20)

	tcpChecksum := tcpChecksumCalc(pseudoHeader, frame[tcpStart:tcpStart+20])
	binary.BigEndian.PutUint16(frame[tcpStart+16:tcpStart+18], tcpChecksum)

	return frame
}

// constructRSTFrame builds a bare RST segment (no ACK, no options) with the
// given sequence number. It closes out the half-open connection a SYN scan
// leaves behind after receiving a SYN/ACK: without it, the target keeps that
// connection in its SYN-RECEIVED backlog until its own retransmit timer
// gives up, which is both impolite at scale and a stealth-scan tell.
func constructRSTFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32) []byte {
	frame := make([]byte, 54)

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ipStart := 14
	frame[ipStart] = 0x45
	binary.BigEndian.PutUint16(frame[ipStart+2:ipStart+4], 40)
	binary.BigEndian.PutUint16(frame[ipStart+4:ipStart+6], 0x1236)
	binary.BigEndian.PutUint16(frame[ipStart+6:ipStart+8], 0x4000)
	frame[ipStart+8] = 64
	frame[ipStart+9] = 6
	copy(frame[ipStart+12:ipStart+16], srcIP.To4())
	copy(frame[ipStart+16:ipStart+20], dstIP.To4())
	ipChecksum := xdpChecksum(frame[ipStart : ipStart+20])
	binary.BigEndian.PutUint16(frame[ipStart+10:ipStart+12], ipChecksum)

	tcpStart := 34
	binary.BigEndian.PutUint16(frame[tcpStart:tcpStart+2], srcPort)
	binary.BigEndian.PutUint16(frame[tcpStart+2:tcpStart+4], dstPort)
	binary.BigEndian.PutUint32(frame[tcpStart+4:tcpStart+8], seq)
	binary.BigEndian.PutUint32(frame[tcpStart+8:tcpStart+12], 0)
	frame[tcpStart+12] = 0x50 // data offset = 5 words, no options
	frame[tcpStart+13] = 0x04 // RST only
	binary.BigEndian.PutUint16(frame[tcpStart+14:tcpStart+16], 0)
	binary.BigEndian.PutUint16(frame[tcpStart+18:tcpStart+20], 0)

	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6
	binary.BigEndian.PutUint16(pseudoHeader[10:12], 20)

	tcpChecksum := tcpChecksumCalc(pseudoHeader, frame[tcpStart:tcpStart+20])
	binary.BigEndian.PutUint16(frame[tcpStart+16:tcpStart+18], tcpChecksum)

	return frame
}

// constructACKFrame builds a bare TCP ACK segment used purely as a host
// discovery probe (RFC 793 requires any host with a live TCP/IP stack to
// answer an out-of-context ACK with a RST, whether or not the port is
// listening) rather than to negotiate a real connection.
func constructACKFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	frame := make([]byte, 54)

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ipStart := 14
	frame[ipStart] = 0x45
	binary.BigEndian.PutUint16(frame[ipStart+2:ipStart+4], 40)
	binary.BigEndian.PutUint16(frame[ipStart+4:ipStart+6], 0x1238)
	binary.BigEndian.PutUint16(frame[ipStart+6:ipStart+8], 0x4000)
	frame[ipStart+8] = 64
	frame[ipStart+9] = 6
	copy(frame[ipStart+12:ipStart+16], srcIP.To4())
	copy(frame[ipStart+16:ipStart+20], dstIP.To4())
	ipChecksum := xdpChecksum(frame[ipStart : ipStart+20])
	binary.BigEndian.PutUint16(frame[ipStart+10:ipStart+12], ipChecksum)

	tcpStart := 34
	binary.BigEndian.PutUint16(frame[tcpStart:tcpStart+2], srcPort)
	binary.BigEndian.PutUint16(frame[tcpStart+2:tcpStart+4], dstPort)
	binary.BigEndian.PutUint32(frame[tcpStart+4:tcpStart+8], 0x11223344)
	binary.BigEndian.PutUint32(frame[tcpStart+8:tcpStart+12], 0x11223345)
	frame[tcpStart+12] = 0x50
	frame[tcpStart+13] = 0x10 // ACK only
	binary.BigEndian.PutUint16(frame[tcpStart+14:tcpStart+16], 1024)
	binary.BigEndian.PutUint16(frame[tcpStart+18:tcpStart+20], 0)

	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6
	binary.BigEndian.PutUint16(pseudoHeader[10:12], 20)

	tcpChecksum := tcpChecksumCalc(pseudoHeader, frame[tcpStart:tcpStart+20])
	binary.BigEndian.PutUint16(frame[tcpStart+16:tcpStart+18], tcpChecksum)

	return frame
}

// constructICMPEchoFrame builds an ICMP Echo Request, the classic
// host-discovery probe.
func constructICMPEchoFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, id, seq uint16) []byte {
	const icmpLen = 8
	totalLen := 20 + icmpLen
	frame := make([]byte, 14+totalLen)

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ipStart := 14
	frame[ipStart] = 0x45
	binary.BigEndian.PutUint16(frame[ipStart+2:ipStart+4], uint16(totalLen))
	binary.BigEndian.PutUint16(frame[ipStart+4:ipStart+6], 0x1239)
	binary.BigEndian.PutUint16(frame[ipStart+6:ipStart+8], 0x4000)
	frame[ipStart+8] = 64
	frame[ipStart+9] = 1 // ICMP
	copy(frame[ipStart+12:ipStart+16], srcIP.To4())
	copy(frame[ipStart+16:ipStart+20], dstIP.To4())
	ipChecksum := xdpChecksum(frame[ipStart : ipStart+20])
	binary.BigEndian.PutUint16(frame[ipStart+10:ipStart+12], ipChecksum)

	icmpStart := ipStart + 20
	frame[icmpStart] = 8 // Echo Request
	frame[icmpStart+1] = 0
	binary.BigEndian.PutUint16(frame[icmpStart+4:icmpStart+6], id)
	binary.BigEndian.PutUint16(frame[icmpStart+6:icmpStart+8], seq)
	icmpChecksum := xdpChecksum(frame[icmpStart : icmpStart+icmpLen])
	binary.BigEndian.PutUint16(frame[icmpStart+2:icmpStart+4], icmpChecksum)

	return frame
}

func constructUDPFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	frameLen := 14 + totalLen

	frame := make([]byte, frameLen)

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ipStart := 14
	frame[ipStart] = 0x45
	binary.BigEndian.PutUint16(frame[ipStart+2:ipStart+4], uint16(totalLen))
	binary.BigEndian.PutUint16(frame[ipStart+4:ipStart+6], 0x1235)
	binary.BigEndian.PutUint16(frame[ipStart+6:ipStart+8], 0x4000)
	frame[ipStart+8] = 64
	frame[ipStart+9] = 17
	copy(frame[ipStart+12:ipStart+16], srcIP.To4())
	copy(frame[ipStart+16:ipStart+20], dstIP.To4())
	ipChecksum := xdpChecksum(frame[ipStart : ipStart+20])
	binary.BigEndian.PutUint16(frame[ipStart+10:ipStart+12], ipChecksum)

	udpStart := ipStart + 20
	binary.BigEndian.PutUint16(frame[udpStart:udpStart+2], srcPort)
	binary.BigEndian.PutUint16(frame[udpStart+2:udpStart+4], dstPort)
	binary.BigEndian.PutUint16(frame[udpStart+4:udpStart+6], uint16(udpLen))

	if len(payload) > 0 {
		copy(frame[udpStart+8:], payload)
	}

	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 17
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(udpLen))

	udpChecksum := tcpChecksumCalc(pseudoHeader, frame[udpStart:udpStart+udpLen])
	if udpChecksum == 0 {
		udpChecksum = 0xffff
	}
	binary.BigEndian.PutUint16(frame[udpStart+6:udpStart+8], udpChecksum)

	return frame
}

func constructIPinIPEthernetFrame(srcMAC, dstMAC net.HardwareAddr, outerSrcIP, outerDstIP net.IP, innerIPPacket []byte) []byte {

	innerIPPayload := innerIPPacket[14:]

	outerIPHeaderLen := 20
	outerIPTotalLen := outerIPHeaderLen + len(innerIPPayload)
	outerIPHeader := make([]byte, outerIPHeaderLen)

	outerIPHeader[0] = 0x45
	outerIPHeader[1] = 0x00
	binary.BigEndian.PutUint16(outerIPHeader[2:4], uint16(outerIPTotalLen))
	binary.BigEndian.PutUint16(outerIPHeader[4:6], 0x0000)
	binary.BigEndian.PutUint16(outerIPHeader[6:8], 0x4000)
	outerIPHeader[8] = 64
	outerIPHeader[9] = 4
	binary.BigEndian.PutUint16(outerIPHeader[10:12], 0x0000)
	copy(outerIPHeader[12:16], outerSrcIP.To4())
	copy(outerIPHeader[16:20], outerDstIP.To4())

	outerIPChecksum := xdpChecksum(outerIPHeader)
	binary.BigEndian.PutUint16(outerIPHeader[10:12], outerIPChecksum)

	outerIPPacket := append(outerIPHeader, innerIPPayload...)

	ethernetFrameLen := 14 + len(outerIPPacket)
	ethernetFrame := make([]byte, ethernetFrameLen)

	copy(ethernetFrame[0:6], dstMAC)
	copy(ethernetFrame[6:12], srcMAC)
	binary.BigEndian.PutUint16(ethernetFrame[12:14], 0x0800)

	copy(ethernetFrame[14:], outerIPPacket)

	return ethernetFrame
}

func xdpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func tcpChecksumCalc(pseudoHeader, tcpData []byte) uint16 {
	payload := append(pseudoHeader, tcpData...)
	return xdpChecksum(payload)
}
