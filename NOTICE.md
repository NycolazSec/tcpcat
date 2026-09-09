# Legal and Authorized Use Notice

## Project Status

tcpcat is a dual-use, open-source network assessment tool maintained as a non-commercial community passion project. It is not sold as a commercial product and does not provide hosted scanning, managed assessments, paid support, customer accounts, or a service operated on behalf of users.

The project is intended for learning, network administration, defensive security research, and authorized security testing.

## Authorization Required

Users must obtain explicit authorization before scanning systems or networks they do not own or administer. The operator is responsible for selecting lawful targets, defining the approved scope, choosing an appropriate maintenance window, and respecting network policies, contracts, privacy requirements, and applicable laws.

For approved assessments, use a documented scope and, where appropriate, the `--scope-file`, `--profile safe-production`, and `--audit-log` options.

## Dual-Use Capabilities

Features such as SYN, UDP, ACK, decoy traffic, fragmentation, source-port selection, timing variation, and packet inspection have legitimate uses in authorized network administration and IDS/IPS visibility testing. They can also be misused. tcpcat does not endorse unauthorized access, disruption, credential theft, persistence, or concealment of unlawful activity.

These features do not guarantee IDS/IPS bypass, reduced detection, access to a target, or successful exploitation of a vulnerability.

## Sanctions and Export Controls

The project does not make a representation that use, distribution, or access to tcpcat is compliant with the laws of every jurisdiction. Users are responsible for complying with applicable sanctions, export-control rules, import restrictions, and local regulations, including rules that may apply to their organization, destination, or use case.

This notice is not legal advice and does not constitute an OFAC, export-control, or regulatory compliance certification. Obtain qualified legal advice when your distribution or use may be subject to sanctions or export controls.

## No Warranty or Compliance Guarantee

tcpcat is provided under the Apache-2.0 license and without warranty, to the extent permitted by law. A detected banner or version is not proof that a vulnerability is exploitable. A `version-based` CVE match requires validation by the responsible team, and scan results may contain false positives, false negatives, or effects caused by filtering and network conditions.

The authors do not guarantee compliance with OFAC, EAR, GDPR, computer-misuse laws, or any other regulation. Users remain responsible for their own legal and operational decisions.

## Contributions

Contributions should preserve authorized-use documentation and must not intentionally add functionality whose primary purpose is unauthorized access, disruption, credential theft, persistence, or concealment of unlawful activity. Pull requests should include relevant tests and documentation updates.
