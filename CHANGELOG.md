# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).
Full diffs for every release are available via GitHub's
[compare view](https://github.com/NycolazSec/tcpcat/compare) and
[Releases page](https://github.com/NycolazSec/tcpcat/releases).

## [Unreleased]

### Added
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
