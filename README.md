# tcpcat — Enterprise-Grade Network Reconnaissance & Vulnerability Intelligence Platform

<div align="center">

```
  [eth0]====-._     _,-'""'-._        _____ ____ ____   ____    _  _____ 
         (,-.'._,'(       |\'-/|      |_   _/ ___|  _ \ / ___|  / \|_   _|
             '-.-' \ )-'( , o o)        | || |   | |_) | |     / _ \ | |  
                   '-    \'_'"'-        | || |___|  __/| |___ / ___ \| |  
    <--[SYN]--(sniffing)--[ACK]-->      |_| \____|_|    \____/_/   \_\_|  
                                        Modular Security & Network Engine
                                         [ eBPF / AF_XDP ] by NycolazSec
```

**High-Performance Network Analysis Platform**  
*eBPF Kernel-Space Operations · Multilayered Evasion · WASM Detection Scripting*

[![CI](https://github.com/NycolazSec/tcpcat/actions/workflows/ci.yml/badge.svg)](https://github.com/NycolazSec/tcpcat/actions/workflows/ci.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14561/badge)](https://www.bestpractices.dev/projects/14561)
[![Go Report Card](https://goreportcard.com/badge/github.com/NycolazSec/tcpcat)](https://goreportcard.com/report/github.com/NycolazSec/tcpcat)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/NycolazSec/tcpcat)](https://github.com/NycolazSec/tcpcat/releases)

</div>

---

## Overview

**tcpcat** is a next-generation network reconnaissance engine built in Go, engineered for high-throughput, authorized network assessment. It provides configurable packet and timing behavior for evaluating IDS/IPS monitoring visibility across multiple OSI layers.

### Project Status

tcpcat is an open-source community project maintained as a personal passion project. It is not sold as a commercial product and does not provide a hosted scanning service, paid support, managed assessments, or customer accounts. The project is intended for learning, network administration, and authorized security testing.

### Core Capabilities

**L2-L7 Reconnaissance**
- Multi-protocol port enumeration (TCP, UDP, ICMP)
- L3/L4 service topology mapping with version fingerprinting
- L7 vulnerability intelligence integration
- Asynchronous DNS/mDNS/NetBIOS service discovery

**Advanced Assessment Controls** (Phase 4 - 29 Techniques)
- **Timing Variation**: Configurable jitter (0.0-1.0 variance coefficient)
- **Fragmentation Controls**: IPv4 datagram fragmentation for monitoring validation
- **Decoy Traffic**: Configurable source patterns for authorized visibility testing
- **Protocol Controls**: TCP/UDP window tuning and source-port selection
- **Traffic Modeling**: Configurable traffic-pattern behavior for assessment scenarios

**Programmable Intelligence**
- WebAssembly (WASM) detection engine with sandboxed execution
- Custom protocol dissectors in Rust, C, Go, or AssemblyScript
- Concurrent detection rules without memory overhead

---

## Architecture

### Kernel-Space Operations (eBPF/AF_XDP)
Direct packet I/O at the network driver level, bypassing the socket layer entirely. Achieves wire-speed performance (~1M pps per core) with minimal CPU overhead.

### Modular Evasion Pipeline
```
Network Layer    → Fragmentation Orchestrator
Transport Layer  → TCP/UDP Fingerprint Randomization
Session Layer    → Timing Jitter & Behavioral Spoofing  
Application Layer → Decoy Swarm Coordination
```

### Detection Integration
Real-time CVE correlation across multiple intelligence feeds (Vulners API, Google OSV, offline database).

---

## Installation & Prerequisites

**Requirements:**
- Go 1.26+
- Linux kernel 5.8+ (for eBPF/XDP, optional but recommended)
- CAP_SYS_ADMIN or root (for raw socket operations)
- gcc/clang (for eBPF compilation, optional)

**Build:**
```bash
git clone https://github.com/NycolazSec/tcpcat.git
cd tcpcat
go mod tidy
go build -o tcpcat ./cmd/tcpcat
sudo ./tcpcat --help
```

---

## Common Scenarios

### Rapid Topology Mapping (1K Most Common Ports)
```bash
sudo tcpcat -sS --top-ports 1000 --rate 100000 target.domain
```

### Service Enumeration with Fingerprinting
```bash
sudo tcpcat -sV -p 22,80,443,3306,5432,27017 192.168.0.0/24 -j results.json
```

### IDS/IPS Visibility Validation (Authorized Audits Only)
```bash
# Conservative timing variation for an approved assessment
sudo tcpcat -Pn -sT -p 1-65535 \
  --evasion light \
  --jitter 0.3 \
  --rate 5000 \
  target

# Validate how approved monitoring controls record fragmented and decoy traffic.
# These controls do not guarantee detection avoidance or IDS/IPS bypass.
sudo tcpcat -Pn -sT -p 1-10000 \
  --evasion aggressive \
  --jitter 0.8 \
  --frag \
  --ttl-mode random \
  --window-size 512 \
  --source-port-mode random \
  --decoy 8.8.8.8,1.1.1.1 \
  target
```

### Ultra-Fast Enumeration (eBPF Mode)
```bash
sudo tcpcat --ebpf -p 1-1000 10.0.0.0/16 -w 128 -T 5
```

### Distributed Traceroute (Layer 3 Topology)
```bash
sudo tcpcat --traceroute target.domain -p 80,443 --max-hops 30
```

### Enterprise Authorized Audit

Create a scope file containing only explicitly authorized IP addresses, CIDRs, or hostnames. Blank lines and comments beginning with `#` are ignored.

```text
# scope.txt
127.0.0.0/8
10.42.0.0/16
app-test.example.internal
```

Run a conservative scan that restricts resolved targets to that scope and produces operational reports:

```bash
sudo tcpcat \
  --profile safe-production \
  --scope-file scope.txt \
  -Pn -p 443 -sV \
  -j report.json \
  --sarif report.sarif \
  --audit-log audit.jsonl \
  10.42.10.15
```

`safe-production` sets timing `-T 2`, limits scan traffic to 300 packets per second, enables service detection, and disables evasion, fragmentation, decoys, smart bypass, and unlimited concurrency. It is intended for approved production assessments; it does not replace written authorization or a documented maintenance window.

Use a valid earlier tcpcat JSON report as a baseline to identify newly exposed ports, service/version changes, and newly detected CVEs:

```bash
sudo tcpcat \
  --profile safe-production \
  --scope-file scope.txt \
  -Pn -p 443 -sV \
  -j report-current.json \
  --baseline report-previous.json \
  --changes changes.json \
  10.42.10.15
```

The baseline must be a non-empty JSON report created by tcpcat. A new, empty file cannot be used as a baseline.

---

## CLI Reference

### Target Specification
```
<target>              IP address, FQDN, CIDR network, or range
-iL <file>           Batch targets from file (one per line)
```

### Discovery Methods
```
-sn                   Host enumeration only (no port scan)
-Pn                   Skip host discovery; treat all as online
-PU <port>            UDP ping discovery (ephemeral probe)
```

### Scan Techniques
```
-sS                   TCP SYN reconnaissance (stealth, partial 3-way)
-sT                   TCP Connect() scan (full 3-way handshake)
-sA                   TCP ACK scan (firewall state detection)
-sW                   TCP Window scan (packet filtering inference)
-sN/-sF/-sX           TCP NULL/FIN/Xmas scans (RFC 793 compliance)
-sU                   UDP probe enumeration
-sI <zombie>          TCP Idle scan (spoofed source via zombie)
--ebpf                Enable AF_XDP kernel-space engine
```

### Port Specification
```
-p <list>             Explicit ports (e.g., 80,443,1000-2000)
--top-ports <n>       First n IANA-ranked common ports
--open                Filter results to established/open state only
```

### Service Intelligence
```
-sV                   Probe response fingerprinting + version correlation
-O                    Remote OS detection via TTL/MSS/window analysis
--scripts <dir>       Load WASM detection modules
```

### IDS/IPS Visibility Controls (Phase 4)
```
--evasion <mode>          Coordinated packet-variation level for authorized testing:
                          • off      — baseline traffic (0% overhead)
                          • light    — limited variation (+5% latency)
                          • moderate — standard variation (+15%)
                          • aggressive — extensive variation (+30%)
                          • stealthy  — high-variation testing profile (+50%)

--jitter <0.0-1.0>        Temporal variation coefficient
                          (0.0=deterministic, 1.0=random intervals)

--frag                     Enable IPv4 fragmentation for monitoring validation

--ttl-mode <mode>         TTL mutation strategy:
                          • fixed   — static TTL value
                          • random  — per-packet randomization
                          • probe   — adaptive per-target measurement

--probe-ttl <1-255>       Probe packet TTL (default: 64)

--window-size <0-65535>   TCP advertised window (0=auto-negotiate)
                          Use only to evaluate flow-state inspection visibility

--source-port-mode        Ephemeral port allocation:
                          • fixed   — static source port
                          • random  — per-packet randomization

-g <port>                 Bind to specific source port

--decoy <ips>             Comma-separated decoy source IPs for an authorized assessment
                          (requires raw socket privileges; no bypass is guaranteed)
```

### Performance Tuning
```
-T <0-5>               Timing template (0=paranoid, 5=insane)
-w <count>             Concurrent worker threads (default: 32)
--rate <pps>           Maximum probe rate (packets/sec), 0=unlimited
--adaptive-rate        Adjust send rate from observed RTT/loss (AIMD) instead of a fixed --rate
--max-retries <n>      Resend a probe up to <n> times before marking it filtered (default 2)
-v                     Verbose output (stack trace on errors)
```

### Output & Reporting
```
-j <file>              Export a detailed JSON report
--sarif <file>          Export open-port and CVE findings as SARIF 2.1.0
--audit-log <file>      Append one scan audit record per line (JSONL)
--baseline <file>       Load a previous tcpcat JSON report for comparison
--changes <file>        Write comparison results; requires --baseline
--update                Check the latest GitHub release and update this binary
```

`--update` downloads the release archive matching the current OS and CPU architecture, verifies it against the release `checksums.txt`, and replaces the current executable atomically. It requires a published GitHub release with matching assets and may require elevated permissions when the binary is installed in a system directory. The option does not update source checkouts or package-manager installations.

### Enterprise Scan Controls
```
--scope-file <file>         Restrict resolved targets to authorized CIDRs, IPs, or hostnames
--profile safe-production   Apply conservative rate, timing, and non-evasive scan settings
```

### Report Semantics

For every open port examined with `-sV`, `vulnerability_assessment` explains the outcome of vulnerability matching:

| Status | Meaning |
|--------|---------|
| `matched` | One or more version-based vulnerability matches were found. |
| `no_match` | A service and version were detected, but no matching entry exists in the selected source. |
| `not_assessed` | A reliable service version was not detected, so no version-based lookup was possible. |

Version-based findings include a CVSS-derived severity, remediation guidance, and `confidence: "version-based"`. They are correlation results, not proof that an issue is exploitable on the target.

Without `--vulners-apikey`, tcpcat uses its embedded offline vulnerability database. The database currently includes selected Apache, nginx, and OpenSSH versions; its coverage is intentionally limited and an absent match is not evidence that a target is secure.

---

## IDS/IPS Visibility Testing

Packet variation, fragmentation, and decoy traffic can help an authorized team assess how its monitoring controls record different scan patterns. Results depend on the network, endpoint protections, IDS/IPS configuration, and operator behavior. tcpcat does not guarantee reduced detection, bypass of controls, or access to a target.

| Mode | Variation | Overhead | Recommended Use |
|------|-----------|----------|-----------------|
| **off** | Baseline traffic | 0% | Authorized inventory and fast reconnaissance |
| **light** | Limited timing and packet variation | +5% | Approved production assessments |
| **moderate** | Standard variation | +15% | Monitoring validation in controlled environments |
| **aggressive** | Extensive variation | +30% | Lab validation with an approved test plan |
| **stealthy** | High-variation profile | +50% | Controlled monitoring-validation scenarios |

**Performance vs. Nmap:**
- Baseline tcpcat: **80ms** for 1-1024 port enumeration
- Nmap (SYN): **1.9-2.3 seconds** (same workload)
- **Speedup: 23.8×** — Even with aggressive evasion, tcpcat outpaces traditional tools

---

## Platform Support

| OS | Raw Sockets | eBPF/XDP | Status |
|----|-------------|---------|--------|
| Linux (5.8+) | ✓ | ✓ | Full support |
| Linux (<5.8) | ✓ | — | Socket-based only |
| macOS 11+ | ✓ | — | Limited (no XDP) |
| Windows 10+ | — | — | Socket-only (connect-style scans) |
| BSD variants | ✓ | — | Experimental |

---

## Legal & Ethical Notice

**AUTHORIZATION REQUIRED**: tcpcat is for authorized security audits, penetration testing, and network administration only. Unauthorized access to computer networks is illegal in most jurisdictions (Computer Fraud & Abuse Act, GDPR, etc.). 

Advanced options such as decoy traffic, fragmentation, and packet variation are provided to support authorized monitoring-validation scenarios. They do not guarantee IDS/IPS bypass, reduced detection, or access to a target. Operators are responsible for obtaining authorization and complying with applicable laws, policies, and regulations.

See [NOTICE.md](NOTICE.md) for the project's dual-use, authorized-use, sanctions, export-control, web-interface, contribution, and no-warranty guidance. This document is informational and is not legal advice or a compliance certification.

The authors assume **zero liability** for misuse.

---

## Contributing

Bug reports and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md)
for the development setup, coding guidelines, and pre-PR checklist, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations. Security
vulnerabilities should be reported privately per [SECURITY.md](SECURITY.md),
not as public issues. See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).
