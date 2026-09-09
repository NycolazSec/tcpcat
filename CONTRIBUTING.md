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

- Go 1.25 or later (see `go.mod`)
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

## License

By contributing, you agree that your contributions will be licensed under the
project's [Apache License 2.0](LICENSE).
