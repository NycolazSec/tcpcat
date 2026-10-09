# tcpcat Security Assessment

This assessment lists the most likely and most impactful security problems that
could occur in tcpcat itself, how each is mitigated today, and what risk remains.
It covers the actors and boundaries described in [ARCHITECTURE.md](ARCHITECTURE.md).
It is reviewed at every minor release. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

Last reviewed: v1.4.3 (2026-10).

## Summary

| # | Threat | Likelihood | Impact | Status |
|---|--------|-----------|--------|--------|
| 1 | Malicious replies from scanned hosts exploit a parser | Medium | High | Mitigated; residual risk (no fuzzing yet) |
| 2 | A bug is amplified by elevated privileges (root / eBPF) | Low | High | Mitigated by design |
| 3 | The XDP program disrupts the host's own traffic | Low | Medium | Mitigated |
| 4 | Scans leave the authorized scope or disrupt fragile devices | Medium | High | Mitigated (operator controls) |
| 5 | Local web UI is driven by another site or exposed on the network | Medium | Medium | **Open: see below** |
| 6 | Self-update installs a tampered binary | Low | High | Partially mitigated |
| 7 | A compromised dependency or toolchain | Low | High | Mitigated |
| 8 | Secrets leak (API keys, webhook URLs, reports) | Medium | Medium | Mitigated; operator guidance |
| 9 | A malicious WASM detection script | Low | Medium | Mitigated (sandbox) |
| 10 | Sensitive scan data is sent to third parties | Medium | Low | Opt-in; documented |

## Details

### 1. Malicious replies from scanned hosts
Targets are untrusted and can send malformed packets, oversized lengths, or hostile
banners, certificates and headers, aiming to crash tcpcat or inject content into
reports.
- **Mitigations:** protocol decoders check bounds and reject oversized length
  fields (for example, the SSH packet reader caps packets at 35,000 bytes); banners
  are sanitized before display; the HTML report uses `html/template`, so host data
  is auto-escaped (covered by a test with a hostile CVE title); reads have deadlines,
  so a slow host cannot hang a scan.
- **Residual risk:** parsers are covered by unit tests but not by continuous
  fuzzing. Adding Go native fuzz tests for the packet/banner decoders is planned.

### 2. Privilege amplification
Raw-socket scans need root or `CAP_NET_RAW`, and the eBPF engine needs
`CAP_SYS_ADMIN`/`CAP_BPF`, so any memory-safety or logic bug runs with those rights.
- **Mitigations:** written in memory-safe Go; connect scans (`-sT`) and most
  features run unprivileged; elevated rights are only needed for the scan types that
  require them.
- **Guidance:** prefer `-sT` or granting only `CAP_NET_RAW` over running as root.

### 3. XDP program side effects
The eBPF engine attaches an XDP program to the scan interface, which often also
carries the operator's SSH session.
- **Mitigations:** the program redirects only replies tcpcat is waiting for and
  returns `XDP_PASS` for everything else; it is detached deterministically on
  exit; native-mode attach falls back to generic mode instead of failing.

### 4. Out-of-scope or disruptive scanning
The most likely real-world harm is scanning systems without authorization, or
overloading fragile industrial equipment.
- **Mitigations:** `--scope-file` restricts resolved targets (also enforced by the
  web UI); `--exclude`; the `safe-production` and `ot` profiles (low rate, no crafted
  packets); rate limiting; a JSONL `--audit-log`; prominent authorized-use notices
  in the README and NOTICE.md.

### 5. Local web UI (`--web`)
The web UI exposes `POST /api/scan`, which starts a scan. It listens on
`127.0.0.1:8080` by default and has no authentication or Origin/Host check.
- **Risk:** a malicious page open in the operator's browser can send a cross-site
  POST to the loopback address (or use DNS rebinding), and a non-loopback
  `--web-addr` exposes the API to the network.
- **Current mitigations:** loopback-only default; a configured `--scope-file` still
  limits what can be scanned.
- **Planned fix:** reject requests whose `Host`/`Origin` is not the local listener,
  and require a per-session token for `/api/scan`. Until then, run `--web` only when
  needed, keep the default loopback address, and always pair it with `--scope-file`.

### 6. Self-update integrity (`--update`)
- **Mitigations:** the release metadata and archive are fetched over HTTPS from
  GitHub; the archive's SHA-256 must match the release's `checksums.txt`; the binary
  is replaced atomically.
- **Residual risk:** `--update` does not yet verify the cosign signature on
  `checksums.txt`, so a compromised GitHub account or release would not be detected
  by the updater. Users can verify manually (see README, "Verifying a release").
  Verifying the signature inside `--update` is planned.

### 7. Supply chain
- **Mitigations:** Go modules with `go.sum` hash verification; weekly Dependabot
  updates; `govulncheck`, `gosec` and `golangci-lint` in CI; least-privilege workflow
  permissions; releases built in CI, signed with keyless cosign and shipped with a
  CycloneDX SBOM per archive.

### 8. Secret handling
- **Risks:** `--vulners-apikey` on the command line shows up in shell history and
  process listings; webhook URLs act as bearer secrets; reports contain sensitive
  network data.
- **Mitigations:** all report, comparison and audit files are created with mode
  `0600`; the README tells operators to treat webhook URLs as secrets.
- **Guidance:** keep secrets in a `--config` file with mode `0600` rather than on the
  command line.

### 9. WASM detection scripts
- **Mitigations:** scripts run in a wazero sandbox with no host functions, no
  filesystem and no network access.
- **Guidance:** only load scripts from sources you trust.

### 10. Data shared with third parties
Vulnerability lookups send product names and versions to OSV or Vulners;
`--exploit-intel` sends CVE IDs to FIRST.org; `--notify-webhook` sends findings to
the configured endpoint.
- **Mitigations:** target IP addresses are not sent to vulnerability feeds; KEV/EPSS
  enrichment and webhooks are opt-in; the offline database works without network
  access.
