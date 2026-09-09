# Phase 5: Deep Packet Inspection & Surgical Scanning

## Overview

**Deep Inspect Mode** (`--deep-inspect`) is an advanced feature for network professionals and security engineers who need surgical, layer-by-layer packet analysis. This mode provides comprehensive visibility into network communication at all OSI layers (L2-L7) with detailed packet dissection, timing analysis, and protocol sequence tracing.

**Use Case:** Authorized network professionals, penetration testers, network engineers, and security researchers conducting detailed protocol analysis and forensic investigations.

---

## Why Deep Inspection?

Traditional port scanners provide basic open/closed/filtered status. Deep Inspect goes much deeper:

| Aspect | Traditional Scan | Deep Inspect |
|--------|-----------------|--------------|
| **Visibility** | Port state only | Full L2-L7 OSI stack |
| **Speed** | Very fast | Slower (surgical) |
| **Detail Level** | Minimal | Maximum |
| **Hex Dump** | No | Yes (full packet) |
| **Timing** | No | Per-packet + inter-packet |
| **Protocol Trace** | No | Full 3-way handshake visible |
| **TTL Analysis** | Basic | Detailed hop-by-hop |
| **Window Analysis** | No | TCP window size tracking |
| **Use Case** | Fast enumeration | Detailed forensics |

---

## CLI Options

### Primary Option

```bash
--deep-inspect
```
Enables surgical packet-level analysis mode. Automatically enables related analysis options.

### Granular Control Options

```bash
--osi-verbosity <1-7>
```
Controls OSI layer detail level:
- **1** = L3 only (minimal overhead)
- **2** = L3 + L2 (MAC headers)
- **3** = L3 + L2 + basic L4
- **4** = Full L1-L4 (default)
- **5** = L1-L4 + detailed IP analysis
- **6** = L1-L6 + application layer analysis
- **7** = Full dissection (maximum detail)

```bash
--hex-dump
```
Display raw packet data in hex + ASCII format (16 bytes per line). Shows:
- Hexadecimal representation
- ASCII printable characters
- Non-printable as dots

```bash
--capture
```
Enable raw packet capture for offline analysis. Stores all captured packets for post-processing.

```bash
--timing-analysis
```
Show inter-packet timing and latency metrics:
- Per-packet timestamp
- Delta timing between packets (Δ milliseconds)
- RTT (round-trip time) measurements
- Network jitter analysis

```bash
--payload-analysis
```
Dissect L7 application layer data:
- Protocol identification
- Banner grabbing
- Service fingerprinting details
- Payload content analysis

```bash
--protocol-trace
```
Trace full protocol negotiation sequence:
- TCP 3-way handshake (SYN → SYN-ACK → ACK)
- TLS handshake (if applicable)
- Application protocol negotiation
- State machine progression

---

## Output Format

### Example: Basic Deep Inspection

```bash
$ sudo tcpcat -Pn -sT -p 22,80 --deep-inspect 192.168.1.100

[PACKET ANALYSIS]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[L3 - Network Layer (IP)]
  Source IP:      192.168.1.10
  Destination IP: 192.168.1.100
  TTL:            64

[L4 - Transport Layer (TCP)]
  Source Port:    54321
  Dest Port:      22
  TCP Flags:      [SYN]
  Sequence Num:   2891234567 (0xacfd0e87)
  Window Size:    65535 bytes

[Timing & Metrics]
  Timestamp:      2026-08-28 23:30:15.042356
  RTT Latency:    1.234ms

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Example: Full Hex Dump (OSI Verbosity 7)

```bash
$ sudo tcpcat -Pn -sT -p 22 --deep-inspect --osi-verbosity 7 --hex-dump 192.168.1.100

[L7 - Application Layer]
  Data Length:    20 bytes

--- HEX DUMP (16 bytes/line) ---
  0000: 53 53 48 2d 32 2e 30 2d  4f 70 65 6e 53 53 48 5f   SSH-2.0-OpenSSH_
  0010: 37 2e 34 70 31                                       7.4p1
```

### Example: Protocol Trace (3-Way Handshake)

```bash
$ sudo tcpcat -Pn -sT -p 443 --protocol-trace 192.168.1.100

[PROTOCOL NEGOTIATION SEQUENCE]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  →  1. [SYN]     Client → Server  (Initiate connection, SEQ=X, flags=[SYN])
  ←  2. [SYN-ACK] Server → Client  (Accept connection, SEQ=Y, ACK=X+1, flags=[SYN,ACK])
  →  3. [ACK]     Client → Server  (Acknowledge, SEQ=X+1, ACK=Y+1, flags=[ACK])
  →  4. [DATA]    Bidirectional    (Application data exchange, flags=[PSH,ACK])

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Example: Timing Analysis

```bash
$ sudo tcpcat -Pn -sT -p 22,80 --timing-analysis 192.168.1.100

[INTER-PACKET TIMING ANALYSIS]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Timeline                                               Δ (ms)
  ─────────────────────────────────────────────────────────────────────
  23:30:15.000 → 23:30:15.001  1 ms
  23:30:15.001 → 23:30:15.003  2 ms
  23:30:15.003 → 23:30:15.005  2 ms
  23:30:15.005 → 23:30:15.042  37 ms (high latency - firewall/IDS analysis)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Real-World Scenarios

### Scenario 1: SSH Service Identification (Port 22)

```bash
sudo tcpcat -Pn -sT -p 22 \
  --deep-inspect \
  --osi-verbosity 6 \
  --payload-analysis \
  --protocol-trace \
  target.example.com
```

**What you'll see:**
- Full TCP 3-way handshake breakdown
- SSH banner (OpenSSH version, build)
- TTL analysis (OS fingerprinting)
- Window size (network stack identification)
- Response timing (server responsiveness)

### Scenario 2: Web Server Analysis (Port 80/443)

```bash
sudo tcpcat -Pn -sT -p 80,443 \
  --deep-inspect \
  --osi-verbosity 7 \
  --hex-dump \
  --timing-analysis \
  target.example.com
```

**What you'll see:**
- HTTP response headers in hex
- Complete TCP connection timing
- Server response delays
- Banner grabbing (Server header)
- SSL/TLS negotiation sequence

### Scenario 3: Firewall State Analysis (ACK Scan + Deep Inspect)

```bash
sudo tcpcat -sA -p 1-65535 \
  --deep-inspect \
  --osi-verbosity 5 \
  --timing-analysis \
  target.example.com
```

**What you'll see:**
- Which ports return RST (unfiltered)
- Which ports return no response (filtered)
- TTL values per port (hop counting)
- Firewall response timing patterns
- Stateful inspection detection

### Scenario 4: Network Topology Discovery

```bash
sudo tcpcat --traceroute -p 443 \
  --deep-inspect \
  --osi-verbosity 5 \
  --timing-analysis \
  target.example.com
```

**What you'll see:**
- Per-hop TTL analysis
- Intermediate router response times
- Network latency at each hop
- Potential packet filtering locations

---

## Advanced Techniques

### Protocol Anomaly Detection

Deep Inspect helps identify abnormal network behavior:

```bash
# Detect port knocking sequences
sudo tcpcat -p 1-65535 \
  --deep-inspect \
  --timing-analysis \
  --protocol-trace \
  target.example.com

# Look for:
# - Sequential port access with specific timing
# - Unusual TTL values (non-standard hops)
# - Window size inconsistencies
```

### IDS/IPS Detection

Identify if target is behind security appliances:

```bash
sudo tcpcat -Pn -sT -p 22,80,443 \
  --deep-inspect \
  --osi-verbosity 6 \
  --timing-analysis

# Look for:
# - Consistent inter-packet delays (indicative of inspection)
# - Identical TTL decrements across multiple ports
# - Repetitive window size patterns
```

### OS Fingerprinting

Operating system identification via L3/L4 parameters:

```bash
sudo tcpcat -sS --top-ports 100 \
  --deep-inspect \
  --osi-verbosity 5

# Analyze:
# - Initial TTL (Linux: 64, Windows: 128)
# - TCP window sizes (OS-specific defaults)
# - MSS (Maximum Segment Size)
# - TCP option ordering
```

---

## Performance Considerations

### Speed Impact

| Mode | Overhead | Typical Scan Time |
|------|----------|------------------|
| Normal scan | 0% | 5-10 seconds |
| Light deep-inspect | +50% | 7-15 seconds |
| Full deep-inspect (OSI 7) | +200-300% | 15-30 seconds |

### Resource Usage

Deep Inspect increases:
- **Memory:** ~10-50MB per 1000 packets (depending on OSI verbosity)
- **CPU:** Additional 2-4 cores for packet dissection
- **Disk I/O:** Significant if `--capture` is enabled

### Recommendations

- Use OSI verbosity 4-5 for balanced analysis
- Enable `--hex-dump` only for suspicious ports
- Use `--capture` sparingly (generates large files)
- Reduce target scope when using full deep inspection

---

## Integration with Evasion

Deep Inspect can be combined with Phase 4 evasion options for advanced reconnaissance:

```bash
# Stealthy deep inspection
sudo tcpcat -Pn -sT -p 22,80,443 \
  --evasion moderate \
  --jitter 0.5 \
  --deep-inspect \
  --osi-verbosity 6 \
  --timing-analysis \
  target.example.com

# Result: Stealthy enumeration with full packet visibility
```

---

## Limitations & Warnings

⚠️ **Important Considerations:**

1. **Slower Scanning:** Deep Inspect significantly reduces scan speed
2. **Network Load:** Increased traffic due to detailed analysis
3. **Large Output:** Verbose output can be overwhelming
4. **Authorization:** Only use on authorized targets
5. **False Positives:** Some timing patterns may be misleading
6. **Firewall Interference:** Some firewalls may rate-limit detailed scanning

---

## CLI Examples

```bash
# Basic deep inspection with default settings
tcpcat -Pn -sT -p 22,80,443 --deep-inspect 192.168.1.100

# Full protocol dissection with hex dump
tcpcat -Pn -sT -p 22 --deep-inspect --osi-verbosity 7 --hex-dump 192.168.1.100

# Stealthy deep inspection (combined with Phase 4 evasion)
tcpcat -Pn -sT -p 22-25 --evasion light --jitter 0.3 --deep-inspect 192.168.1.100

# Timing analysis only (minimal overhead)
tcpcat -Pn -sT -p 22,80 --timing-analysis 192.168.1.100

# Protocol trace + timing for specific services
tcpcat -Pn -sT -p 22,80,443 --protocol-trace --timing-analysis 192.168.1.100

# Maximum detail with everything enabled
tcpcat -Pn -sT -p 22 --deep-inspect --osi-verbosity 7 --hex-dump \
  --timing-analysis --payload-analysis --protocol-trace 192.168.1.100
```

---

## For Network Professionals

This feature is designed specifically for:
- **Network Engineers** — Detailed topology mapping
- **Security Researchers** — Protocol vulnerability research
- **Penetration Testers** — Authorized deep reconnaissance
- **Forensic Investigators** — Network evidence collection
- **IDS/IPS Engineers** — Evasion technique testing

**Remember:** This tool is for authorized use only. Always obtain written permission before scanning networks you don't own.

---

Version: Phase 5 v1.0
Date: 2026-08-28
Status: Professional-Grade Feature
