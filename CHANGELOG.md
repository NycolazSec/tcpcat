# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).
Full diffs for every release are available via GitHub's
[compare view](https://github.com/NycolazSec/tcpcat/compare) and
[Releases page](https://github.com/NycolazSec/tcpcat/releases).

## [Unreleased]

### Added
- TLS/certificate inspection (`internal/service/tls.go`), surfaced as a
  new `TLSInfo` on every `-sV` result for a `443`/`8443` port: negotiated
  TLS version and cipher suite, the presented certificate's subject,
  issuer, and expiry, and a set of human-readable warnings -- self-signed
  certificate, hostname/IP mismatch, expired or expiring within 14 days,
  deprecated protocol version (< TLS 1.2), or a cipher suite from
  `crypto/tls`'s own insecure list. The probe deliberately always dials
  with `InsecureSkipVerify` (a self-signed or expired certificate is
  exactly the finding this exists to surface, not something that should
  make the handshake fail silently) and with `MinVersion: TLS 1.0` (Go's
  client otherwise refuses to even negotiate down far enough to detect a
  server that only offers TLS 1.0/1.1, which is precisely the server this
  is meant to flag). It runs as its own independent, fully-closed
  connection *before* `DetectService`'s main connection opens, rather than
  overlapping with it -- against a server that only services one
  connection at a time, two simultaneous connections to the same probe
  left the second stuck in the accept queue until the first timed out.
- HTTP security posture inspection (`internal/service/http_posture.go`),
  surfaced as a new `HTTPPosture` on every `-sV` result for a web port
  (`80`/`443`/`8080`/`8443`/`8000`/`8888`): flags missing security response
  headers (`Content-Security-Policy`, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, and `Strict-Transport-Security`
  when the connection is actually TLS -- it's meaningless over plain HTTP,
  so it's only checked there) and whether a small set of well-known
  sensitive paths (`.git/HEAD`, `.git/config`, `.env`) are genuinely
  exposed. Each sensitive-path check requires a body-content signature
  match on top of a `200` status (e.g. `.git/HEAD`'s body must actually
  contain `ref:`), not a bare status-code check -- a lot of real sites (SPA
  routers, custom error/fallback pages) return `200` for literally any
  path, which would otherwise flag every single one of them. Uses its own
  `net/http` client (correct header/redirect/chunked-encoding handling,
  redirects disabled since the check is about *this* host's own response)
  rather than hand-parsing the existing raw-socket banner grab, and -- same
  reasoning and same fix as the TLS probe above -- runs to full completion
  before `DetectService`'s main connection opens, never overlapping it.
- `--max-retries <n>` (default 2): a stateless probe (SYN/ACK/Window/FIN/
  NULL/Xmas/UDP, over both the raw-socket and AF_XDP paths) is resent up to
  `n` times before the target is reported filtered, instead of a single
  packet loss silently misclassifying an open port. Each retry's wait is
  sized from the shared RTT estimator's RFC 6298-style RTO once it has
  real samples (`RTTEstimator.RTO`, previously computed but never used),
  falling back to the `-T` timing template's fixed timeout until then.
- Randomized scan dispatch order (`internal/scan/permute.go`): the
  target*port job queue is now fed through an O(1)-memory full-period LCG
  permutation (the same cycle-walking technique `RandomCIDRGenerator`
  already used for a single CIDR) instead of strict list order, so a scan
  interrupted partway through has sampled an unbiased slice of the whole
  target list instead of only the first few hosts. Final results are
  unaffected (`engine.go` still sorts by IP then port). `--no-randomize`
  restores the old strict list-order dispatch.
- Expanded service detection (`internal/service/engine.go`): passive banner
  recognition for VNC (`RFB ...`), POP3 (`+OK`), IMAP (`* OK`/`* PREAUTH`),
  and MySQL (parses the server version straight out of the protocol-10
  handshake packet MySQL sends unprompted on connect); active protocol
  probes for services that stay silent until spoken to -- Redis (`INFO`,
  parsing `redis_version`), Memcached (`version`), PostgreSQL (an
  `SSLRequest` frontend message, confirming the protocol and whether TLS
  is offered pre-auth), SMB (an SMB2 `NEGOTIATE` request, reporting the
  server's chosen dialect from 2.0.2 through 3.1.1), and RDP (an X.224
  Connection Request carrying an RDP Negotiation Request, reporting the
  security layer -- Standard/TLS/CredSSP -- the server selects). Every new
  prober fails closed: a rejected or unrecognized reply just falls back to
  the existing port-based name guess, never worse than before.
- Expanded OS fingerprint database (`internal/osdetect/fingerprint.go`):
  grew from 4 to 9 curated TCP/IP stack signatures -- split the combined
  "Cisco IOS / Solaris" entry into two (Cisco's minimal MSS-only stack vs.
  Solaris's full SACK+Timestamps option set, both at TTL 255), and added
  Linux 2.x (no timestamps, smaller default window/scale than 3.x+),
  Windows XP/Server 2003 (SACK but no window scaling at all), OpenBSD
  (timestamps off by default), and IBM AIX. Every new entry was checked to
  actually score higher against its own signature than every other table
  entry does, so the larger table can't introduce ties that make `Match`'s
  result depend on iteration order instead of the observed signature.
- Expanded offline vulnerability database (`internal/vuln/offline.go`):
  grew from 4 CVE entries across 3 products to 13 entries across 6
  (apache, nginx, openssh, redis, mysql, vsftpd), covering well-known,
  publicly documented CVEs -- e.g. Apache's CVE-2021-42013 (the RCE bypass
  of CVE-2021-41773's incomplete fix, affecting both 2.4.49 and 2.4.50),
  OpenSSH's CVE-2024-6387 ("regreSSHion") and CVE-2023-38408, Redis's
  CVE-2022-24735/24736 Lua sandbox escapes, and vsftpd 2.3.4's well-known
  backdoor (CVE-2011-2523). This is still a hand-picked seed list, not a
  full mirror of the NVD -- `UpdateOfflineDB`/`AddSoftwareToOfflineDB`
  remain the way to layer a fuller feed into the user's own copy of the
  database.
- ARP-based local subnet discovery, layered onto the existing AF_XDP host
  discovery path: `DiscoverHostsXDP` now also fires a raw ARP request for
  any candidate IP that falls inside the scanning interface's own subnet
  (tracked via a new `localSubnet` alongside the existing `localIP`), and
  `xdpRxLoop` recognizes ARP replies (EtherType `0x0806`) instead of
  silently dropping every non-IPv4 frame as before. A host with every
  routable probe (ICMP/TCP/UDP) firewalled off still has to answer ARP to
  receive any traffic at all on its own local segment, so this catches
  hosts the existing ICMP/SYN/ACK probes would otherwise miss.
- Multi-queue AF_XDP: `InitXDPEngine` no longer hardcodes `queueID := 0`.
  It now reads the interface's actual RX queue count from sysfs
  (`getInterfaceRXQueueCount`) and binds one AF_XDP socket per queue, each
  mapped into `xsks_map` at its own index, with one `xdpRxLoop` goroutine
  per queue feeding the same shared results maps. Previously, a NIC with
  RSS enabled (routine on multi-core cloud VMs and real server hardware)
  would spread inbound replies across several hardware queues by flow
  hash, and a socket bound to queue 0 alone only ever saw whichever
  fraction happened to land there -- the rest were never delivered to
  user space at all, not merely dropped after arriving. Falls back to a
  single queue (today's exact behavior) wherever the count can't be read
  or a later queue's socket fails to bind, so this can't turn into a
  regression on a single-queue NIC or in a container.
- IPv6 target support for the connect scan, UDP scan, and service
  detection paths (`internal/target`): `ParseTarget` now accepts literal
  IPv6 addresses directly instead of silently dropping them via a
  leftover `.To4()` filter, and falls back to a hostname's AAAA records
  when it has no A records instead of erroring with "no IPv4 address
  found". `expandCIDR` now expands IPv6 CIDRs too, capped at 20 host bits
  (~1M addresses, e.g. a /108) since a wider IPv6 prefix has vastly more
  addresses than any scan -- or this process's memory -- could hold,
  unlike IPv4's bounded 32-bit space. `-sT`, `-sU`, and `-sV` need no
  changes themselves; they already dialed generically via
  `net.JoinHostPort`/`net.Dial`. Also fixed the evasion `CustomDialer`'s
  `--ttl` option, which set `IP_TTL` (the IPv4 sockopt) unconditionally
  and so silently no-op'd on an IPv6 connection; it now sets
  `IPV6_UNICAST_HOPS` when dialing over IPv6.
  The raw-socket scan techniques (`-sS/-sA/-sW/-sN/-sF/-sX`) and `--ebpf`
  remain IPv4-only -- their packet-crafting layers would need a genuinely
  new IPv6 header/checksum implementation this couldn't be validated
  without live IPv6 network testing -- but now say so clearly
  ("raw-socket scans ... only support IPv4; use -sT or -sU for an IPv6
  target") instead of the previous bare "invalid IPv4 address".
- AF_XDP-accelerated host discovery (`internal/scan/xdp_discovery.go`):
  `DiscoverHostsXDP` fires ICMP Echo, TCP SYN/443, and TCP ACK/80 probes
  over the existing zero-copy AF_XDP path instead of shelling out to `ping`
  and blocking on sequential TCP dials; `cmd/tcpcat` uses it automatically
  whenever the eBPF/XDP engine is active.
- Automatic RST on the AF_XDP SYN scan path: `xdpRxLoop` now closes out a
  half-open connection immediately after recording its SYN/ACK, instead of
  leaving it in the target's backlog until its own retransmit timer expires.
- Structured OS fingerprinting (`internal/osdetect/fingerprint.go`): a small
  curated signature database (Linux, Windows, macOS/BSD, Cisco/Solaris)
  scored on TTL bucket, window scale, MSS, SACK/timestamps, and TCP option
  order, surfaced as a best-guess name and confidence alongside the existing
  raw signature string.
- Adaptive timing (`internal/scan/adaptive_rate.go`): a lock-free RTT
  estimator (RFC 6298-style SRTT/RTTVAR EWMA) and an AIMD rate controller,
  enabled with the new `--adaptive-rate` flag to pace scans from observed
  loss instead of a fixed `--rate`.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and issue/PR templates.
- Static analysis (`go vet`, `golangci-lint`), a `gosec` security scan, and
  `govulncheck` dependency scanning in CI, in addition to the existing
  build-and-test job.

### Fixed
- `internal/scan/engine.go`: **`-sT --ebpf` was silently promoted to a raw
  XDP SYN scan.** The AF_XDP gate excluded the *other* raw scan types
  (`-sA/-sW/-sN/-sF/-sX`) but never checked for an explicit `-sT`
  (`ConnectScan`), so `!isOtherRawScan` was true and the connect scan a
  user asked for got redirected into raw SYN crafting instead of a real
  three-way handshake through the kernel. Against a loopback target this
  is actively harmful: AF_XDP frames are always addressed to the
  gateway's MAC on the physical interface, so `-sT --ebpf 127.0.0.1`
  pushed a martian packet (`dst=127.0.0.1`) out onto the wire instead of
  routing it locally. New `xdpEligible(ip, opts)` gate: an explicit
  `-sT`, or any loopback target (`127.0.0.0/8`, `::1`), now always falls
  through to the kernel stack even with `--ebpf` active. `cmd/tcpcat`
  also now warns when `--ebpf` is used on Linux at all, since generic/SKB
  mode (no zero-copy on most virtualized NICs) hooks *all* RX traffic on
  the auto-detected interface -- typically the same one the operator's
  own SSH session uses, and a fast scan can starve it.
- `internal/scan/engine.go`, `adaptive_rate.go`: **the rate limiter paced
  jobs, not packets**, so the real TX rate ran at a multiple of `--rate`.
  A single job on the raw-socket / AF_XDP path emits `probeAttempts()`
  retransmits (3 by default) plus one frame per `--decoy`, and the old
  per-job `time.Ticker` charged exactly one slot for all of them -- a
  "1000 pps" scan actually put ~3000+ SYN/s on the wire, and the decoy
  frames escaped the limit entirely. On a fast NIC this turns a large scan
  into an RX-side packet storm (every SYN draws a SYN-ACK/RST back). The
  fixed and adaptive paths are now one lock-free evenly-spaced pacer
  (`AdaptiveRateLimiter.WaitN`; a fixed rate is the AIMD controller pinned
  with `min==max`), and each job reserves its true packet count
  (`attempts + decoys`) up front. An evenly-spaced pacer is used rather
  than a token bucket on purpose: the goal is to *smooth* the returning
  flood, and a token bucket's burst-up-to-capacity allowance would just
  recreate it in chunks.
- `internal/scan/raw_tcp.go`: **on Linux, the raw-socket SYN/ACK/Window/
  NULL/FIN/Xmas scan path (`-sS/-sA/-sW/-sN/-sF/-sX`) could never actually
  see a reply.** Every probe's socket was opened with `IPPROTO_RAW`, which
  Linux documents as send-only (`raw(7)`) -- it implies `IP_HDRINCL` for
  crafting a custom header on the way out, but the kernel gives it no
  receive queue at all, so every reply, including a genuine SYN-ACK from
  an open port, was silently invisible and every scan bottomed out at
  `filtered`/timeout regardless of the real target state. This had nothing
  to do with target reachability or timing -- it reproduced 100% of the
  time against a target confirmed open by nmap from the same host. Fixed
  by receiving through a dedicated shared socket opened with
  `IPPROTO_TCP` instead (sending is unaffected, still `IPPROTO_RAW`); that
  socket now demultiplexes replies to whichever in-flight probe is
  waiting for them (keyed by target IP + probed port + our source port),
  the same shared-receiver design `internal/scan/xdp.go`'s `xdpRxLoop`
  already used for the AF_XDP path. This also fixes a real concurrency
  gap the old per-job-socket code had: a raw socket receives a copy of
  *all* matching traffic on the interface regardless of which job opened
  it, and the old per-socket filter never checked the reply's source IP,
  so two concurrent probes to the same port on different hosts could
  cross-match. Verified against real raw sockets in a `--cap-add=NET_RAW`
  Docker container (this machine has no interactive `sudo`) with a live
  listener on one side and `-sS/-sA/-sW/-sN/-sF` from the other, cross-
  checked against `nmap`'s own result for the same target/port. As a side
  effect of no longer keeping one raw socket open per concurrent worker,
  a scan's wall-clock time also stops scaling with worker count for a
  reason unrelated to network conditions -- previously every open raw
  socket received (and had to filter) a copy of all matching traffic on
  the interface, so N concurrent workers meant N-times the per-packet
  filtering overhead system-wide.
- `config/options.go`: `--max-retries <n>` wasn't registered in the CLI's
  custom `valueFlags` pairing table (unlike `--rate`/`-T`/etc.), so its
  pre-parser left `<n>` as a bare positional argument and shifted whatever
  flag followed `--max-retries` into its place -- `--max-retries 0 -T 5`
  failed with `invalid value "-T" for flag -max-retries: parse error`
  instead of setting `MaxRetries=0` and `Timing=5`.
- `internal/scan/deep_inspect.go`: build the dial target with
  `net.JoinHostPort` so IPv6 targets are addressed correctly.
- `internal/scan/xdp.go`: avoid dereferencing `opts.RelayServer` before the
  existing `opts != nil` guard in `ScanXDPPort`/`ScanXDPUDPPort`; also
  record latency and a best-guess OS on successful SYN scans, which were
  previously left unset.
- `cmd/tcpcat/main.go`: report a lookup error instead of silently continuing
  when both the OSV and offline vulnerability scanners fail.
- `internal/service/engine.go`: implement the previously empty nginx
  `<center>nginx/...</center>` banner-signature fallback.
- `internal/evasion/fragment.go`: handle odd-length buffers in
  `computeIPChecksum` instead of risking an out-of-range slice access.
- `internal/web/web.go`: serve the local web UI with read/write/idle
  timeouts instead of `http.ListenAndServe`'s unbounded defaults.
- Tightened generated scan-report and offline vulnerability database file
  permissions from world-readable (`0644`/`0755`) to owner-only
  (`0600`/`0700`); extended the same tightening to the previously-missed
  `internal/output/grepable.go`, `normal.go`, and `script_kiddie.go`
  exporters.
- Checked ~30 previously-ignored error returns (mostly `Close()` on
  connections, files, and archive readers, plus a few unchecked
  `fmt.Fprintf` writes) flagged by `golangci-lint`'s default `errcheck` and
  `staticcheck` linters after upgrading to golangci-lint v2; simplified a
  few `if`/`else if` chains into tagged `switch` statements per
  `staticcheck`'s `QF1003`.
- `internal/discovery/ping.go` and `internal/scan/deep_inspect.go`: two more
  dial targets built with `fmt.Sprintf("%s:%d", ...)` instead of
  `net.JoinHostPort`, same IPv6-breaking pattern as the `deep_inspect.go`
  fix above.
- Split `internal/scan/xdp_craft.go`: the AF_XDP frame builders
  (`constructSYNFrame` and friends) are Linux-only and now live in the new,
  `//go:build linux`-tagged `internal/scan/xdp_frames.go`; the shared
  `xdpChecksum` helper (also used by the cross-platform raw-socket scanner)
  stays behind with no build tag.

### Changed
- CI: `golangci-lint-action` v6 → v9, which pulls golangci-lint v2 by
  default; the Go toolchain used for linting is `"stable"` again instead of
  pinned to `"1.25"`, since v2 (unlike the old v1.64.x prebuilt binary) can
  read the export data of current Go compilers.
- Bumped `actions/checkout` v4 → v7, `actions/setup-go` v5 → v7, and
  `goreleaser/goreleaser-action` v6 → v7 across both workflows; bumped
  `golang.org/x/sys` v0.43.0 → v0.48.0 and `github.com/tetratelabs/wazero`
  v1.7.2 → v1.12.0, which raises this module's minimum Go version to
  `1.26.0`.
- `release.yml`: the `macos-installers` job now has `timeout-minutes: 20`
  and `continue-on-error: true`, so a GitHub-side macOS runner queue stall
  (observed repeatedly on this project) no longer requires a manual cancel
  and can no longer mark an otherwise-successful release as failed; the
  Linux/macOS/Windows archives and Linux packages from the `goreleaser` job
  are unaffected either way.

## [1.0.1]

- CI/release pipeline improvements: GoReleaser v2, Linux/macOS installer
  publishing, and Windows release build support.

## [1.0.0]

- Initial public release: multi-protocol port scanning (TCP/UDP/ICMP),
  service/version fingerprinting, offline and OSV-backed vulnerability
  correlation, eBPF/AF_XDP high-throughput scanning on Linux, IDS/IPS
  visibility-testing controls, and a WASM-based scripting engine for custom
  detectors and exploit modules.

[Unreleased]: https://github.com/NycolazSec/tcpcat/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/NycolazSec/tcpcat/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/NycolazSec/tcpcat/releases/tag/v1.0.0
