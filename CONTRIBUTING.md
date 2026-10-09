# Contributing to tcpcat

Thanks for your interest in improving tcpcat. This project is a non-commercial,
community-maintained network reconnaissance tool intended for authorized
security testing, network administration, and learning. Please read
[NOTICE.md](NOTICE.md) before contributing — it describes the dual-use,
authorized-use guidance that all changes must respect.

## Code of Conduct

Participation in this project is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to abide
by its terms.

## Reporting bugs

- Search [existing issues](https://github.com/NycolazSec/tcpcat/issues) before opening a new one.
- File functional bugs, build problems, and feature requests as
  [GitHub Issues](https://github.com/NycolazSec/tcpcat/issues/new/choose).
- Include your OS/kernel version, `tcpcat` version (`tcpcat --version`), the
  exact command you ran, and the observed vs. expected behavior.
- **Do not** file security vulnerabilities as public issues — see
  [SECURITY.md](SECURITY.md) for the private disclosure process.

## Development setup

Requirements:

- Go 1.26 or later (see `go.mod`)
- Linux with kernel 5.8+ if you're working on the eBPF/AF_XDP path
  (`internal/scan/xdp*.go`); other platforms build and run the socket-based
  scan engine only.

```bash
git clone https://github.com/NycolazSec/tcpcat.git
cd tcpcat
go build ./cmd/tcpcat
go test ./...
```

Cross-platform release binaries can be built with `make build-all` (see the
[Makefile](Makefile)).

## Dependencies

**How dependencies are obtained.** tcpcat is a Go module. All third-party
code comes in through Go modules: `go.mod` pins each dependency's version and
`go.sum` records its cryptographic hash, which the Go toolchain verifies
(against the public Go checksum database) on every download. Nothing is
vendored or fetched outside of Go modules.

**How dependencies are selected.** Prefer the Go standard library. A new
third-party module is added only when it is actively maintained, widely used,
and under a license compatible with tcpcat's licensing (see [LICENSE](LICENSE)
and [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)). A pull request that adds
one must say why the standard library or an existing dependency isn't enough.

**How dependencies are tracked.**
- [Dependabot](.github/dependabot.yml) checks Go modules and GitHub Actions
  weekly and opens update pull requests; they go through the same CI as any
  other change.
- CI runs `govulncheck` and `gosec` on every push to `main` and every pull
  request against it, so a
  newly disclosed vulnerability in a dependency (or the Go standard library)
  fails the build.
- Every release ships a CycloneDX SBOM per archive listing the exact modules
  and versions it was built from.

## Before opening a pull request

Run the same checks CI runs:

```bash
gofmt -l .                 # must print nothing
go vet ./...
go test -race ./...
go build ./cmd/tcpcat
```

If you have [golangci-lint](https://golangci-lint.run/) installed:

```bash
golangci-lint run ./...
```

Guidelines:

- Keep pull requests focused on a single change; unrelated fixes should be
  separate PRs.
- Add or update tests for behavioral changes. New scan techniques, evasion
  primitives, or parsers should have unit test coverage.
- Update `README.md`, `docs/`, and CLI `--help` text when you change
  user-facing behavior or flags.
- Follow standard Go formatting (`gofmt`) and idioms; keep exported
  identifiers documented with a doc comment.
- Per [NOTICE.md](NOTICE.md), contributions must preserve the authorized-use
  documentation and must not add functionality whose primary purpose is
  unauthorized access, disruption, credential theft, persistence, or
  concealment of unlawful activity.

## Commit / PR conventions

- Write commit messages that explain *why* a change was made, not just what
  changed.
- Reference the related issue number in the PR description when applicable.
- A maintainer will review and may request changes before merging. Please be
  responsive to review feedback; PRs with no activity for an extended period
  may be closed and can be reopened when you're ready to continue.

## License and Contributor License Agreement

tcpcat is dual-licensed: it is published under the
[GNU Affero General Public License v3.0](LICENSE) and also offered under a
[commercial license](COMMERCIAL-LICENSE.md). Versions up to and including
v1.4.1 were released under the Apache License 2.0.

Before your first pull request can be merged, you must accept the
[Contributor License Agreement](CLA.md). You keep the copyright in your work.
The CLA lets the project distribute your contribution under both licenses, and
commits the project to keeping every accepted contribution available under the
AGPL-3.0 or another OSI-approved license.

The CLA Assistant bot comments on your first pull request. To sign, reply:

> I have read the CLA Document and I hereby sign the CLA

You only sign once. The CLA check runs on every pull request and must pass for
each commit author before merging.
