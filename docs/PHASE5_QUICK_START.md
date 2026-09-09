# Phase 5 Deep Inspection - Quick Start Guide

## What is Deep Inspection?

Deep Inspection (`--deep-inspect`) is a surgical, layer-by-layer packet analysis mode for professional network engineers and security researchers. It shows **exactly how packets communicate** at every OSI layer.

**Speed Trade-off:** Slower but reveals everything about the network communication.

---

## Quick Examples

### 1. Basic Deep Inspection (SSH)

```bash
sudo tcpcat -Pn -sT -p 22 --deep-inspect 192.168.1.100
```

**Output shows:**
- TCP 3-way handshake breakdown
- SSH banner (OpenSSH version)
- TTL value (OS fingerprinting)
- TCP window size
- Response timing

### 2. See Everything in Hex (Detailed Inspection)

```bash
sudo tcpcat -Pn -sT -p 80 --deep-inspect --osi-verbosity 7 --hex-dump 192.168.1.100
```

**Output shows:**
- Full HTTP response in hexadecimal
- ASCII representation of data
- Byte-by-byte packet structure

### 3. Watch Packet Timing (Network Analysis)

```bash
sudo tcpcat -Pn -sT -p 22,80,443 --timing-analysis 192.168.1.100
```

**Output shows:**
- Exact time each packet is sent/received
- Time between packets (Δ milliseconds)
- Identifies firewall delays or IDS inspection

### 4. See Full Handshake (Protocol Tracing)

```bash
sudo tcpcat -Pn -sT -p 22 --protocol-trace 192.168.1.100
```

**Output shows:**
```
→  1. [SYN]     Client → Server
←  2. [SYN-ACK] Server → Client
→  3. [ACK]     Client → Server
→  4. [DATA]    Bidirectional
```

---

## All Phase 5 Options

| Option | Purpose | Example |
|--------|---------|---------|
| `--deep-inspect` | Enable full analysis | `--deep-inspect` |
| `--osi-verbosity <1-7>` | Detail level (1=minimal, 7=max) | `--osi-verbosity 5` |
| `--hex-dump` | Show packet hex + ASCII | `--hex-dump` |
| `--capture` | Save packets to file | `--capture` |
| `--timing-analysis` | Show inter-packet delays | `--timing-analysis` |
| `--payload-analysis` | Analyze L7 application data | `--payload-analysis` |
| `--protocol-trace` | Show handshake sequence | `--protocol-trace` |

---

## OSI Verbosity Levels

```
1 = L3 only (IP header)
2 = L3 + L2 (IP + Ethernet)
3 = L3 + L2 + basic L4 (IP + Ethernet + TCP)
4 = Full L1-L4 (EVERYTHING about transport)
5 = L1-L4 + detailed IP (includes DSCP, flags, fragmentation)
6 = + L7 (application layer data preview)
7 = Full dissection (hex dump + everything)
```

**Recommendation:** Start with `--osi-verbosity 4` (default when using `--deep-inspect`)

---

## Common Scenarios

### Scenario: "I want to see EVERYTHING about how port 22 is communicating"

```bash
sudo tcpcat -Pn -sT -p 22 \
  --deep-inspect \
  --osi-verbosity 7 \
  --hex-dump \
  --protocol-trace \
  --timing-analysis \
  192.168.1.100
```

### Scenario: "I want to detect if there's a firewall/IDS in front"

```bash
sudo tcpcat -Pn -sT -p 22,80,443 \
  --timing-analysis \
  192.168.1.100

# Look for: Consistent delays between packets = inspection
```

### Scenario: "I want to identify the operating system"

```bash
sudo tcpcat -sS --top-ports 10 \
  --deep-inspect \
  --osi-verbosity 5 \
  192.168.1.100

# Look for: TTL (64=Linux, 128=Windows), TCP window size
```

### Scenario: "I want stealthy + detailed analysis"

```bash
sudo tcpcat -Pn -sT -p 22,80 \
  --evasion light \
  --jitter 0.3 \
  --deep-inspect \
  --osi-verbosity 5 \
  192.168.1.100
```

---

## What You'll See (Example Output)

```
[PACKET ANALYSIS]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[L3 - Network Layer (IP)]
  Source IP:      192.168.1.10
  Destination IP: 192.168.1.100
  TTL:            64          ← Linux (64) or Windows (128)?

[L4 - Transport Layer (TCP)]
  Source Port:    54321       ← Ephemeral port
  Dest Port:      22          ← Target port
  TCP Flags:      [SYN]       ← Connection initiation
  Sequence Num:   2891234567  ← Random initial sequence
  Window Size:    65535       ← Max advertised window

[Timing & Metrics]
  Timestamp:      2026-08-28 23:30:15.042356
  RTT Latency:    1.234ms     ← Server response time

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Performance Tips

| Mode | Speed | Best For |
|------|-------|----------|
| Normal scan | ⚡⚡⚡ | Fast enumeration |
| `--timing-analysis` | ⚡⚡ | Firewall detection |
| `--deep-inspect` (default) | ⚡ | Balanced detail |
| `--deep-inspect --osi-verbosity 7` | 🐢 | Maximum forensics |

**Faster:** Use `--osi-verbosity 4` or `--timing-analysis` only  
**Slower but detailed:** Use `--osi-verbosity 7 --hex-dump`

---

## For Network Professionals

### Network Engineers
```bash
# Detailed topology mapping
sudo tcpcat -Pn -sT -p 1-1000 --deep-inspect --timing-analysis 10.0.0.0/24
```

### Security Researchers
```bash
# Protocol vulnerability research
sudo tcpcat -Pn -sT -p 22 --deep-inspect --osi-verbosity 7 --hex-dump --payload-analysis
```

### Penetration Testers (Authorized)
```bash
# Detailed reconnaissance with stealth
sudo tcpcat -Pn -sT -p 22,80,443 --evasion light --deep-inspect --timing-analysis
```

### Forensic Investigators
```bash
# Full packet capture for analysis
sudo tcpcat -Pn -sT -p 22,80 --deep-inspect --capture --hex-dump
```

---

## When to Use Deep Inspection

✅ **USE WHEN:**
- You need to understand **exactly** how packets are being exchanged
- Performing authorized network forensics
- Testing IDS/IPS systems (authorized)
- Researching network protocols
- Verifying firewall rules

❌ **DON'T USE WHEN:**
- You just need a quick port scan (use normal mode)
- On unauthorized targets
- Speed is critical
- Scanning large networks (use `--timing-analysis` only)

---

## Key Insights from Deep Inspection

### TTL Analysis
- **Linux:** 64 (or 255 on internal networks)
- **Windows:** 128 (or 255 on internal networks)
- **Cisco/Network equipment:** Often 255

### Window Size Patterns
- **Linux:** Often 29200, 65535
- **Windows:** Often 65535, 8760
- **macOS:** Often 65535

### TCP Flags Sequence
```
Normal flow:  [SYN] → [SYN-ACK] → [ACK] → [DATA]
Closed port:  [RST-ACK] (immediate)
Filtered:     (no response)
```

---

## Full Documentation

See `docs/PHASE5_DEEP_INSPECT.md` for:
- Advanced techniques
- Real-world scenarios
- Performance considerations
- Integration with Phase 4 evasion
- Limitations and warnings

---

## Command Template

```bash
sudo tcpcat \
  -Pn                           # Skip discovery
  -sT                           # TCP Connect scan
  -p <PORTS>                    # Target ports
  --deep-inspect                # Enable surgical analysis
  --osi-verbosity <1-7>         # Detail level
  [--hex-dump]                  # Hex output
  [--timing-analysis]           # Timing data
  [--protocol-trace]            # Handshake visualization
  [--payload-analysis]          # Application data
  <TARGET>
```

---

**Remember:** Always have authorization before scanning networks!

Version: Phase 5 v1.0 Quick Start
