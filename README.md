# tcpcat — a fast network scanner in Go, with an eBPF/AF_XDP engine

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

*eBPF/AF_XDP kernel-space I/O · service & OS detection · CVE correlation · WASM detection scripting*

[![CI](https://github.com/NycolazSec/tcpcat/actions/workflows/ci.yml/badge.svg)](https://github.com/NycolazSec/tcpcat/actions/workflows/ci.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14561/badge)](https://www.bestpractices.dev/projects/14561)
[![Go Report Card](https://goreportcard.com/badge/github.com/NycolazSec/tcpcat)](https://goreportcard.com/report/github.com/NycolazSec/tcpcat)
[![License: AGPL-3.0 or Commercial](https://img.shields.io/badge/License-AGPL--3.0%20or%20Commercial-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/NycolazSec/tcpcat)](https://github.com/NycolazSec/tcpcat/releases)
[![Discord](https://img.shields.io/badge/Discord-Rejoindre-5865F2?logo=discord&logoColor=white)](https://discord.gg/syn)
</div>

Fast network scanner in Go with an eBPF/AF_XDP engine, service and OS
detection, CVE correlation, and JSON/SARIF reports. Built for **authorized**
security assessments.

<!--
  DEMO: record a short terminal GIF of a real scan and drop it at docs/demo.gif,
  then uncomment the line below. A ~10s asciinema/vhs capture of the Quick start
  command works well.
  ![tcpcat demo](docs/demo.gif)
-->

## Quick start

```bash
# Install (Go 1.26+)
go install github.com/NycolazSec/tcpcat/cmd/tcpcat@latest

# Scan an authorized host with service + version detection
sudo tcpcat -sV -p 22,80,443 scanme.nmap.org
```

Prefer a prebuilt binary or a `.deb`/`.dmg`? Grab one from the
[releases page](https://github.com/NycolazSec/tcpcat/releases). To build from
source, see [Installation](#installation--prerequisites).

```text
[*] Target loaded: scanme.nmap.org (1 IP(s) resolved)
[*] Running Host Discovery...
    ├─ [UP] 45.33.32.156
[*] Ports loaded: 3 port(s) targeted
────────────────────────────────────────────────────────────────────────────
[+] 45.33.32.156:22    ─ OPEN  (time=151.73ms | reason=SYN-ACK Received)
[+] 45.33.32.156:80    ─ OPEN  (time=150.57ms | reason=SYN-ACK Received)
[~] 45.33.32.156 ─ Not shown: 1 closed port(s)
────────────────────────────────────────────────────────────────────────────
[*] Running Service & Version Detection...
[v] 45.33.32.156:22    ─ SERVICE: openssh 6.6.1p1 (OS: ubuntu)
[v] 45.33.32.156:80    ─ SERVICE: apache 2.4.7 (OS: ubuntu)
    [!] http: missing security header: Content-Security-Policy
    [!] http: missing security header: X-Frame-Options
────────────────────────────────────────────────────────────────────────────
[*] Running Vulnerability Lookup (Source: OSV API)...
[!] 45.33.32.156:22    - 56 vulnerabilities found for openssh 6.6.1p1
    |_ CVE-2023-38408 (CVSS: 9.8) - insufficiently trustworthy search path in ssh-agent PKCS#11...
    |_ CVE-2020-15778 (CVSS: 7.8) - command injection in scp.c toremote function...
    ... (trimmed)
```

Add `-j report.json` for a full JSON report or `--sarif report.sarif` for
SARIF 2.1.0 output.

> Only scan hosts and networks you own or have explicit written permission to
> test. `scanme.nmap.org` is a public host Nmap provides for scan testing. See
> the [Legal & Ethical Notice](#legal--ethical-notice).

More recipes — eBPF high-throughput scans, OT/ICS, scope files, WASM detection
scripts, AWS discovery — are in [examples/](examples/).

---

## Overview

**tcpcat** is a next-generation network reconnaissance engine built in Go, engineered for high-throughput, authorized network assessment. It provides configurable packet and timing behavior for evaluating IDS/IPS monitoring visibility across multiple OSI layers.

### Project Status

tcpcat is a dual-licensed project (AGPL-3.0 or commercial) maintained by Nicolas Blondelle (NycolazSec). It is **free and open source under the AGPL-3.0**, and does not provide a hosted scanning service, paid support, managed assessments, or customer accounts. Embedding it in a proprietary product or hosted service without the AGPL's copyleft obligations requires a commercial (OEM) license (see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)). The project is intended for learning, network administration, and authorized security testing.

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

**Install with Go (fastest):**
```bash
go install github.com/NycolazSec/tcpcat/cmd/tcpcat@latest
sudo tcpcat --help
```

**Build from source:**
```bash
git clone https://github.com/NycolazSec/tcpcat.git
cd tcpcat
go mod tidy
go build -o tcpcat ./cmd/tcpcat
sudo ./tcpcat --help
```

**Prebuilt packages:** `.deb`, `.dmg`, and per-platform binaries are attached
to each [GitHub release](https://github.com/NycolazSec/tcpcat/releases).

### Verifying a release

Every release ships a `checksums.txt`, a CycloneDX **SBOM** per archive, and a
**cosign** signature of the checksums file (keyless, tied to the GitHub Actions
OIDC identity and logged in Sigstore's public transparency log). To verify an
archive you downloaded:

```bash
# 1. Verify the checksums file was signed by this project's release workflow
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature  checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/NycolazSec/tcpcat/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. Verify your archive's hash is the one listed in the signed checksums file
sha256sum --check --ignore-missing checksums.txt
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

### Industrial / OT networks

Programmable logic controllers, RTUs and other field devices can fault under ordinary scanning: a half-open SYN can wedge a small TCP stack, parallelism and high rates overrun tiny connection tables, and malformed or fragmented packets are exactly the kind of input that trips fragile firmware. The `ot` profile is built for these networks — deliberately gentle rather than stealthy:

```bash
sudo tcpcat --profile ot --scope-file scope.txt 10.10.0.0/24
```

`ot` uses a full TCP connect scan only (never a raw SYN, UDP, or eBPF/AF_XDP scan), one connection at a time (`-w 1`), a 5 packets-per-second rate, timing `-T 1`, and sends nothing crafted — no evasion, fragmentation, decoys, or smart bypass. Service detection stays on but only reads what a device offers; no active protocol query is sent to control-plane ports. When no ports are given, it scans a curated set of industrial control ports and names the protocol behind each open one:

| Protocol | Port | Protocol | Port |
|---|---|---|---|
| S7comm (Siemens) | 102 | OPC UA | 4840 |
| Modbus | 502 | OMRON FINS | 9600 |
| Red Lion Crimson | 789 | DNP3 | 20000 |
| Foundation Fieldbus | 1089/1091 | ProConOS | 20547 |
| Niagara Fox (Tridium) | 1911/4911 | PROFINET | 34962/34964 |
| PCWorx (Phoenix Contact) | 1962 | EtherNet/IP | 2222/44818 |
| IEC 60870-5-104 | 2404 | BACnet | 47808 |
| CODESYS | 2455 | | |

By default, OT ports are named passively — no query is sent to a control port. To read an exact vendor and version (which enables CVE correlation), add `--ot-probe`:

```bash
sudo tcpcat --profile ot --ot-probe -p 502 10.10.0.5
```

`--ot-probe` sends **one well-formed, read-only** protocol query per supported port and parses the reply. Currently supported: Modbus (function 43 / MEI 14, "Read Device Identification" → vendor, product, revision) and EtherNet/IP (encapsulation "List Identity" → product name, revision). It never sends a malformed frame and never writes to or commands the device. It only fires on ports with a registered probe; any other port is still named passively. Because even a legitimate query can disturb the most fragile equipment, `--ot-probe` is strictly opt-in and is never enabled by the `ot` profile on its own.

Even the `ot` profile is not risk-free on the most sensitive equipment. Scan only within an authorized scope and maintenance window, and coordinate with the OT/process owner first.

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
IPv6 literals, IPv6 CIDRs (capped at a /108, ~1M hosts, to avoid trying to
enumerate an infeasible address count), and hostnames that only resolve to
AAAA records are all accepted. `-sT`/`-sU`/service detection work over IPv6
exactly as over IPv4; the raw-socket scan techniques below (`-sS/-sA/-sW/
-sN/-sF/-sX`) and `--ebpf` remain IPv4-only and return a clear error if
pointed at an IPv6 target instead of silently misbehaving.

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
                      (needs -sS or --ebpf on Linux, as root, to read a raw SYN/ACK)
--scripts <dir>       Load WASM detection modules
--jarm                Active JARM TLS fingerprint on TLS ports (opt-in: 10 extra probes/target)
--ot-probe            Read exact vendor/version from OT ports (Modbus...) via one read-only query (opt-in)
--exploit-intel       Enrich correlated CVEs with CISA KEV + EPSS and prioritize by them (opt-in)
```
On a `443`/`8443` port, `-sV` also runs an independent TLS/certificate
probe and attaches the result as `tls` in JSON output: negotiated
version/cipher, certificate subject/issuer/expiry, and warnings for a
self-signed or expired certificate, a hostname mismatch, a deprecated
protocol version (< TLS 1.2), or a known-insecure cipher suite. It always
inspects the certificate presented, valid or not -- an invalid cert is
the finding, not a reason to skip the probe.

The same probe also reports post-quantum readiness (`pqc_group`/`pqc_ready`
in JSON): on TLS 1.3, tcpcat's Go toolchain offers a hybrid ML-KEM key
exchange (`X25519MLKEM768`, `SecP256r1MLKEM768`, or `SecP384r1MLKEM1024`)
by default, so whichever group the target actually negotiates says whether
it's ready for the ongoing NIST post-quantum migration. A TLS 1.3 target
that falls back to a classical group (e.g. plain `X25519`) is flagged with
a warning.

With `--jarm`, `-sV` also computes an active JARM fingerprint (`jarm.hash`
in JSON) on TLS ports: 10 deliberately varied TLS ClientHellos (different
versions, cipher orderings, GREASE, ALPN sets) whose responses are
fuzzy-hashed into a 62-character fingerprint. Two servers running the same
TLS stack/config produce the same JARM hash regardless of hostname or IP --
useful for identifying C2 infrastructure, cloned or rogue servers, and
misconfigured load balancers, and for cross-referencing public JARM
threat-intel feeds. Opt-in because it's 10 extra connections with
non-standard ClientHellos per target, not part of the default `-sV` probe.

On a web port (`80`/`443`/`8080`/`8443`/`8000`/`8888`), `-sV` also runs an
independent HTTP security posture probe and attaches the result as
`http_posture` in JSON output: which common security response headers
(`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
`Referrer-Policy`, and `Strict-Transport-Security` over TLS) are missing,
and whether `.git/HEAD`, `.git/config`, or `.env` are actually exposed --
each checked against the response body's own content, not just its status
code, so a site whose router returns `200` for any path doesn't get
flagged for files that don't really exist.

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
--no-randomize         Dispatch probes in target/port list order instead of a randomized permutation
-v                     Verbose output (stack trace on errors)
```

### Output & Reporting
```
-j <file>              Export a detailed JSON report
-oX <file>              Export XML
-oH <file>              Export a self-contained HTML report (shareable; shows KEV/EPSS when enabled)
-oG <file>              Export grepable output (one line per host)
-oN <file>              Export a plain-text report
-oS <file>              Export leetspeak
--sarif <file>          Export open-port and CVE findings as SARIF 2.1.0
--audit-log <file>      Append one scan audit record per line (JSONL)
--baseline <file>       Load a previous tcpcat JSON report for comparison
--changes <file>        Write comparison results; requires --baseline
--update                Check the latest GitHub release and update this binary
```

Every format may be requested in the same run; each writes its own file.
All of them group results per scanned host, so a CIDR or `-iL` scan
reports each address separately. The XML export carries the full `-sV`
picture — service name/version/OS, the TLS block (negotiated version,
cipher, certificate details, warnings), HTTP posture findings (missing
security headers, exposed paths), and correlated CVEs — rather than just
the port state.

`--update` downloads the release archive matching the current OS and CPU architecture, verifies it against the release `checksums.txt`, and replaces the current executable atomically. It requires a published GitHub release with matching assets and may require elevated permissions when the binary is installed in a system directory. The option does not update source checkouts or package-manager installations.

### Enterprise Scan Controls
```
--scope-file <file>         Restrict resolved targets to authorized CIDRs, IPs, or hostnames
--resume <file>             Resume an interrupted scan: skip target/ports already recorded, append new ones
--exclude <list>            Comma-separated hosts, CIDRs, or names to leave out of the scan
--profile safe-production   Apply conservative rate, timing, and non-evasive scan settings
--profile ot                Gentle profile for fragile industrial/OT networks (PLC/RTU/ICS)
```

### Report Semantics

For every open port examined with `-sV`, `vulnerability_assessment` explains the outcome of vulnerability matching:

| Status | Meaning |
|--------|---------|
| `matched` | One or more version-based vulnerability matches were found. |
| `no_match` | A service and version were detected, but no matching entry exists in the selected source. |
| `not_assessed` | A reliable service version was not detected, so no version-based lookup was possible. |

Version-based findings include a CVSS-derived severity, remediation guidance, and `confidence: "version-based"`. They are correlation results, not proof that an issue is exploitable on the target.

With `--exploit-intel`, tcpcat additionally queries two live feeds and reorders each host's findings so the most urgent lead: CVEs in CISA's **Known Exploited Vulnerabilities (KEV)** catalog (`known_exploited: true` in JSON, `[KEV: exploited in the wild]` in the console) come first, then by **EPSS** score (`epss`/`epss_percentile` in JSON — FIRST.org's predicted 30-day exploitation probability), then by CVSS. This turns a long CVSS-ranked list into a "patch these first" order; a high-CVSS CVE that nobody is exploiting sinks below a medium-CVSS one that is. Enrichment is best-effort and opt-in (it adds network round-trips): offline or on a feed error, findings keep their CVSS-only ordering. KEV/EPSS are prioritization signals, not proof of exploitability on your specific target.

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

**Performance vs. Nmap and naabu (full port range):**

```
hyperfine --warmup 0 --runs 3 \
  -n "tcpcat-ebpf" "./tcpcat -i eth0 -p 1-65535 -sS --ebpf --open -T 5 --rate 25000 <host1> <host2>" \
  -n "naabu"       "naabu -interface eth0 -p 1-65535 -rate 25000 -host <host1>,<host2> -silent" \
  -n "nmap"        "nmap -e eth0 -p 1-65535 -sS -n -T4 --min-rate 25000 --max-retries 1 <host1> <host2>"
```

| Tool | Mean Time | Range (min … max) |
|------|-----------|--------------------|
| **tcpcat (eBPF/XDP)** | **4.466 s ± 0.744 s** | 3.623 s … 5.028 s |
| nmap | 11.723 s ± 0.503 s | 11.150 s … 12.094 s |
| naabu | 20.945 s ± 0.181 s | 20.739 s … 21.077 s |

- **2.62× faster than nmap**, **4.69× faster than naabu** — full 1-65535 SYN scan across 2 hosts, 25K pps rate limit, 3 runs each.

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

**AUTHORIZATION REQUIRED.** tcpcat is a dual-use tool for authorized security
audits, penetration testing, network engineering research, and system
administration only. It is not a hosted or managed scanning service — there
is no remote infrastructure, no user accounts, and no scanning performed on
anyone's behalf by the maintainers. Unauthorized access to, or interference
with, a computer system is a criminal offense in most jurisdictions,
including under the U.S. Computer Fraud and Abuse Act, Articles 323-1 to
323-3-1 of the French *Code pénal*, the UK Computer Misuse Act 1990, and
equivalent statutes elsewhere.

Before scanning any system or network you do not solely own or administer,
you must hold **explicit, written authorization** from its owner, covering a
documented scope and assessment window. The Operator — not the maintainers
— bears full and exclusive criminal and civil responsibility for every
packet the binary emits and every consequence that follows, including
collateral impact, unintended denial of service, and violations of a
network or hosting provider's Acceptable Use Policy.

Advanced options such as decoy traffic, fragmentation, and packet variation
exist to help an authorized team validate what its own IDS/IPS and
monitoring stack records under varied traffic patterns. They are
visibility-testing instruments, not a warranty: they do not guarantee
security-control bypass, reduced detection, or access to a target, and a
version/banner-based CVE match is a lead requiring validation, not
confirmation of exploitability.

tcpcat is provided **"AS IS", with zero warranty and zero liability** for
the authors and contributors, to the maximum extent permitted by law (see
LICENSE §§8–9). See [NOTICE.md](NOTICE.md) for the full legal notice —
software status, operator responsibility, disclaimer of warranty, dual-use
capabilities, sanctions/export-control guidance, and the contribution policy
— and [SECURITY.md](SECURITY.md) to report a vulnerability in tcpcat itself
through a private GitHub Security Advisory. Neither document is legal advice
or a compliance certification.

---

## Contributing

Bug reports and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md)
for the development setup, coding guidelines, and pre-PR checklist, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations. Security
vulnerabilities should be reported privately per [SECURITY.md](SECURITY.md),
not as public issues. See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

tcpcat is **dual-licensed**:

- **GNU Affero General Public License v3.0 (AGPL-3.0)** — free and open source;
  see [LICENSE](LICENSE). You may use, modify, and self-host tcpcat, but if you
  distribute it or offer it to others over a network, you must release your
  product's complete source under the AGPL.
- **Commercial (OEM) license** — for embedding tcpcat in a proprietary product
  or hosted service without the AGPL's copyleft obligations. See
  [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

Versions up to and including **v1.4.1** were released under the Apache License
2.0 ([LICENSE-Apache-2.0.txt](LICENSE-Apache-2.0.txt)) and remain available
under those terms.
