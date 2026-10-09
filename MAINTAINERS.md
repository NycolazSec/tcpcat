# Maintainers

This file lists everyone with access to tcpcat's sensitive resources.

| Name | GitHub | Role |
|------|--------|------|
| Nicolas Blondelle | [@NycolazSec](https://github.com/NycolazSec) | Sole maintainer |

## Roles and responsibilities

**Maintainer** — currently @NycolazSec:
- Reviews and merges pull requests, and keeps CI (build, tests, lint, gosec,
  govulncheck) green on `main`.
- Cuts releases: updates CHANGELOG.md and pushes the `v*` tag that triggers the
  signed release workflow.
- Triages issues and Dependabot updates.
- Handles vulnerability reports privately per [SECURITY.md](SECURITY.md),
  including fixes and advisories.
- Upholds the authorized-use policy in [NOTICE.md](NOTICE.md) and the
  [Code of Conduct](CODE_OF_CONDUCT.md).

**Contributors** — anyone who opens an issue or pull request:
- Follow [CONTRIBUTING.md](CONTRIBUTING.md): focused changes, tests for
  behavioral changes, docs updated for user-facing changes, CI passing.
- Report security issues privately, never as public issues.

## Access to sensitive resources

| Resource | Who has access |
|----------|----------------|
| GitHub repository admin (settings, branch rules, merging to `main`) | @NycolazSec |
| Releases (pushing `v*` tags, which trigger the release workflow) | @NycolazSec |
| GitHub Actions secrets and workflow settings | @NycolazSec |
| Private security advisories (see [SECURITY.md](SECURITY.md)) | @NycolazSec |
| OpenSSF Best Practices project entry | @NycolazSec |

Release artifacts are signed with cosign in **keyless** mode: the signature is
bound to the GitHub Actions workflow identity, so no long-lived signing key
exists for anyone to hold.

To report a security issue, follow [SECURITY.md](SECURITY.md) rather than
contacting a maintainer directly.
