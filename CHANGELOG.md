# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).
Full diffs for every release are available via GitHub's
[compare view](https://github.com/NycolazSec/tcpcat/compare) and
[Releases page](https://github.com/NycolazSec/tcpcat/releases).

## [Unreleased]

### Added
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and issue/PR templates.
- Static analysis (`go vet`, `golangci-lint`), a `gosec` security scan, and
  `govulncheck` dependency scanning in CI, in addition to the existing
  build-and-test job.

### Fixed
- `internal/scan/deep_inspect.go`: build the dial target with
  `net.JoinHostPort` so IPv6 targets are addressed correctly.
- `internal/scan/xdp.go`: avoid dereferencing `opts.RelayServer` before the
  existing `opts != nil` guard in `ScanXDPPort`/`ScanXDPUDPPort`.
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
  (`0600`/`0700`).

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
