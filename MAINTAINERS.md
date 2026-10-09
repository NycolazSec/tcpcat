# Maintainers

This file lists everyone with access to tcpcat's sensitive resources.

| Name | GitHub | Role |
|------|--------|------|
| Nicolas Blondelle | [@NycolazSec](https://github.com/NycolazSec) | Sole maintainer |

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
