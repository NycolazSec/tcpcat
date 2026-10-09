# Security Policy

## Supported Versions
Only the latest major/minor release is actively maintained and patched for security vulnerabilities.

| Version | Supported          |
| ------- | ------------------ |
| 1.4.x   | :white_check_mark: |
| < 1.4   | :x:                |

## Reporting a Vulnerability
If you discover a potential vulnerability in **tcpcat**, please disclose it responsibly:

1. **Do not** open a public GitHub issue.
2. Open a private [GitHub Security Advisory](https://github.com/NycolazSec/tcpcat/security/advisories/new) or send an email to `security@nycolazsec.com`.
3. Provide step-by-step reproduction instructions, payload samples, and system architecture details.

We aim to acknowledge reports within 48 hours and provide patches promptly.

## Coordinated disclosure timeline

- **Acknowledgement:** within 48 hours of the report.
- **Triage:** within 7 days we confirm whether the issue is a vulnerability and
  share an initial severity assessment with the reporter.
- **Fix:** we aim to release a fix within 90 days of the report, sooner for
  critical issues, and keep the reporter informed of progress.
- **Disclosure:** the vulnerability is made public when the fixed release is
  published, or at 90 days if no fix is available, unless the reporter and
  maintainers agree on a different date.

## How vulnerabilities are published

Once a fix is released, every confirmed vulnerability in tcpcat is published
openly:

- as a public **GitHub Security Advisory**, with a CVE ID requested through
  GitHub, the affected and fixed versions, severity, and credit to the reporter
  (unless they prefer to stay anonymous). All advisories are listed at
  <https://github.com/NycolazSec/tcpcat/security/advisories>;
- in the **`### Security`** section of [CHANGELOG.md](CHANGELOG.md) and in the
  release notes of the fixed version.

Published advisories also feed the GitHub Advisory Database and OSV, so
dependency scanners flag affected tcpcat versions.

For authorized-use, dual-use, sanctions, export-control, and web-interface
guidance, see [NOTICE.md](NOTICE.md).