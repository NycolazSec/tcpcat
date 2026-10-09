# tcpcat Architecture

This document describes the actors that interact with tcpcat and every action
the system performs, from command-line input to exported report.

## Actors

| Actor | Trust | Interaction |
|-------|-------|-------------|
| **Operator** | Trusted | Runs the CLI (or the local web UI) and supplies targets, flags, `--config`, `--scope-file`, `--exclude`, baselines and WASM scripts. Responsible for holding authorization for every target. |
| **tcpcat process** | — | The single binary (`cmd/tcpcat`). Runs unprivileged for connect scans; needs root / `CAP_NET_RAW` for raw-socket scans and `CAP_SYS_ADMIN`/`CAP_BPF` for the eBPF/AF_XDP engine. |
| **Scanned targets** | **Untrusted** | Hosts and services being assessed. Everything they send (packets, banners, TLS certificates, HTTP headers, SSH KEXINIT, protocol replies) is untrusted input. |
| **Linux kernel** | Trusted | Raw sockets, and the XDP program tcpcat attaches to the scan interface (eBPF engine only). |
| **Vulnerability feeds** | Semi-trusted | OSV API, Vulners API (with an operator-supplied key), the embedded offline database, CISA KEV and FIRST.org EPSS (`--exploit-intel`). |
| **GitHub Releases API** | Semi-trusted | Source of release metadata and archives for `--update`. |
| **AWS EC2 API** | Semi-trusted | Tag-based target discovery (`--aws-region`/`--aws-tags`), using the operator's AWS credentials. |
| **Webhook receiver** | Semi-trusted | Discord, Slack or HTTP endpoint that receives change alerts (`--notify-webhook`). |
| **Local filesystem** | Trusted (operator-owned) | Config, scope, target lists, baselines/state files, WASM scripts, reports and audit logs. |
| **Browser (web UI)** | Operator's | Talks to the local web interface (`--web`, default `127.0.0.1:8080`). |

## Actions (scan pipeline)

1. **Configuration.** Parse flags; splice in `--config` defaults (the command line
   overrides them); apply a profile (`safe-production`, `ot`); validate options.
2. **Target resolution.** Expand IPs, CIDRs, ranges, hostnames, `-iL` files and
   AWS tag discovery; then restrict to `--scope-file` and drop `--exclude` entries.
3. **Host discovery.** ICMP, TCP and UDP pings, plus ARP on the local segment
   (socket-based, or over AF_XDP with `--ebpf`). `-Pn` skips this step.
4. **Port scanning.** Connect, SYN, ACK, Window, NULL/FIN/Xmas, UDP or idle scans,
   rate-limited (`--rate`, `--adaptive-rate`, timing templates). With `--ebpf`,
   probes are crafted and replies received through AF_XDP; the attached XDP program
   redirects only replies tcpcat is waiting for and passes all other traffic.
5. **Service detection (`-sV`).** Read banners and run active probes (Redis,
   PostgreSQL, SMB, RDP, MQTT, …; UDP payloads such as DNS, SNMP, CoAP, IPMI), TLS
   and certificate analysis, optional JARM, HTTP posture, SSH algorithm posture,
   OS fingerprinting, optional read-only OT probes (`--ot-probe`).
6. **Detection scripts.** Optional WASM modules (`--scripts`) run in a wazero
   sandbox with no host functions or filesystem access.
7. **Vulnerability correlation.** Match detected product/version against OSV,
   Vulners or the offline database (distro-aware); optionally enrich with KEV and
   EPSS and reorder by exploitability.
8. **Comparison and alerting.** Load `--baseline` before exporting, compare, write
   `--changes`, and POST an alert to `--notify-webhook` when something changed.
9. **Reporting.** Console output plus JSON, XML, HTML, SARIF, grepable, normal,
   leetspeak and a JSONL audit log (`--audit-log`). Report files are created with
   mode `0600`.
10. **Optional services.** The local web UI (`--web`) accepts scan requests and
    serves results; `--update` downloads the latest release, verifies its SHA-256
    against the release's `checksums.txt`, and replaces the binary atomically.

## Data flow and trust boundaries

```
Operator ──flags/config/scope──▶ tcpcat ──probes──▶ Targets (untrusted)
                                   ▲   ◀──replies────┘
                                   │
            OSV / Vulners / KEV / EPSS / GitHub / AWS (HTTPS, semi-trusted)
                                   │
                                   ▼
                     Reports, audit log, webhook alert
```

Untrusted data enters at one boundary: replies from scanned targets. It is parsed
by bounds-checked decoders, sanitized before display, and HTML-escaped in reports.
See [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md) for the threats at each boundary.
