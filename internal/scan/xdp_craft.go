// internal/scan/xdp_craft.go
package scan

import (
    "encoding/binary"
    "net"
)

// constructSYNFrame génère un paquet Ethernet > IPv4 > TCP SYN complet en byte array pur.
func constructSYNFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
    // Taille totale : Ethernet (14) + IP (20) + TCP (20) = 54 octets
    frame := make([]byte, 54)

    // ==========================================
    // 1. En-tête ETHERNET (Couche 2) - 14 octets
    // ==========================================
    copy(frame[0:6], dstMAC)              // MAC Destination
    copy(frame[6:12], srcMAC)             // MAC Source
    binary.BigEndian.PutUint16(frame[12:14], 0x0800) // EtherType = IPv4

    // ==========================================
    // 2. En-tête IPv4 (Couche 3) - 20 octets
    // ==========================================
    ipStart := 14
    frame[ipStart] = 0x45      // Version 4, IHL 5
    frame[ipStart+1] = 0x00    // DSCP / ECN
    binary.BigEndian.PutUint16(frame[ipStart+2:ipStart+4], 40) // Longueur totale (IP + TCP)
    binary.BigEndian.PutUint16(frame[ipStart+4:ipStart+6], 0x1234) // Identification
    binary.BigEndian.PutUint16(frame[ipStart+6:ipStart+8], 0x4000) // Flags (Don't Fragment) & Fragment Offset
    frame[ipStart+8] = 64      // TTL (Time To Live)
    frame[ipStart+9] = 6       // Protocole (6 = TCP)
    // Checksum IP initialisé à 0
    binary.BigEndian.PutUint16(frame[ipStart+10:ipStart+12], 0)
    copy(frame[ipStart+12:ipStart+16], srcIP.To4())
    copy(frame[ipStart+16:ipStart+20], dstIP.To4())

    // Calcul du checksum IP
    ipChecksum := xdpChecksum(frame[ipStart : ipStart+20])
    binary.BigEndian.PutUint16(frame[ipStart+10:ipStart+12], ipChecksum)

    // ==========================================
    // 3. En-tête TCP (Couche 4) - 20 octets
    // ==========================================
    tcpStart := 34
    binary.BigEndian.PutUint16(frame[tcpStart:tcpStart+2], srcPort)
    binary.BigEndian.PutUint16(frame[tcpStart+2:tcpStart+4], dstPort)
    binary.BigEndian.PutUint32(frame[tcpStart+4:tcpStart+8], 0x11223344) // Sequence Number
    binary.BigEndian.PutUint32(frame[tcpStart+8:tcpStart+12], 0)         // Acknowledgment Number
    frame[tcpStart+12] = 0x50 // Data Offset (5 * 4 = 20 octets)
    frame[tcpStart+13] = 0x02 // Flags (0x02 = SYN)
    binary.BigEndian.PutUint16(frame[tcpStart+14:tcpStart+16], 64240) // Window Size
    // Checksum TCP initialisé à 0
    binary.BigEndian.PutUint16(frame[tcpStart+16:tcpStart+18], 0)
    binary.BigEndian.PutUint16(frame[tcpStart+18:tcpStart+20], 0) // Urgent Pointer

    // Pseudo-header pour le checksum TCP
    pseudoHeader := make([]byte, 12)
    copy(pseudoHeader[0:4], srcIP.To4())
    copy(pseudoHeader[4:8], dstIP.To4())
    pseudoHeader[8] = 0
    pseudoHeader[9] = 6
    binary.BigEndian.PutUint16(pseudoHeader[10:12], 20) // Longueur TCP

    // Calcul du checksum TCP final
    tcpChecksum := tcpChecksumCalc(pseudoHeader, frame[tcpStart:tcpStart+20])
    binary.BigEndian.PutUint16(frame[tcpStart+16:tcpStart+18], tcpChecksum)

    return frame
}

// xdpChecksum standard IP (Complément à 1)
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