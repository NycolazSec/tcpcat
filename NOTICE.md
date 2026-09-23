# Legal and Authorized Use Notice

This notice governs the use, distribution, and modification of **tcpcat**. It
is incorporated by reference into the [README](README.md) and applies to the
source code, compiled binaries, container images, and any redistribution of
this project, regardless of the channel through which it was obtained.

This document is informational and does not constitute legal advice. It is
not a substitute for consulting qualified counsel in your jurisdiction before
conducting network assessments, distributing the software, or relying on any
statement made here.

## 1. Software Status and Defensive Purpose

tcpcat is a **dual-use** network reconnaissance and security-assessment
engine, released under the Apache License 2.0 as a non-commercial,
community-maintained open-source project.

tcpcat is designed and distributed exclusively for:

- System and network administration (inventory, topology mapping, change
  validation);
- Network engineering research and protocol/education work; and
- Security-posture assessments and penetration tests that are **formally
  authorized in writing** by the owner or operator of the target systems or
  network.

tcpcat is **not**:

- A managed or hosted scanning service. The project does not operate, offer,
  or resell any remote scanning infrastructure on a user's behalf;
- An attack tool, an exploitation framework, or a vector for gaining
  unauthorized access, causing denial of service, exfiltrating data,
  establishing persistence, or concealing unlawful activity. No such
  capability is knowingly included, and none is supported;
- Associated with user accounts, subscriptions, SaaS billing, or any
  commercial engagement between the maintainers and a user's targets.

Any deployment that operates tcpcat as a hosted or managed service, or that
markets scanning "on behalf of" third parties, is undertaken entirely outside
this project and entirely at the deploying party's own risk and legal
responsibility. The maintainers are not a party to, and derive no benefit
from, any such deployment.

Individual capabilities — SYN, UDP, ACK, decoy traffic, fragmentation,
source-port selection, timing variation, and packet inspection — have
legitimate uses in authorized network administration and IDS/IPS visibility
testing, and can also be misused like any other network tool. Their
inclusion does not constitute an endorsement of unauthorized access,
disruption, credential theft, persistence, or concealment of unlawful
activity; see Section 3 for what they do and do not guarantee.

## 2. Sole Responsibility of the Operator

The individual or organization that runs tcpcat (the "Operator") bears **full
and exclusive criminal and civil responsibility** for every packet the binary
emits, every target it is pointed at, and every consequence that follows.
Authorship or distribution of the software does not extend to, and does not
create, any agency, joint-action, or complicity relationship between the
maintainers and the Operator's use of it.

Before scanning, probing, or otherwise assessing any system or network that
the Operator does not solely own or administer, the Operator **must** obtain:

- **Explicit, written authorization** from the system or network owner,
  naming the authorizing party and the person(s) conducting the assessment;
- A **documented scope** (target IP ranges, hostnames, or CIDRs — see
  `--scope-file`), including systems and time windows that are explicitly
  excluded; and
- Agreement on the **assessment window**, applicable rules of engagement,
  and an escalation/abort contact in case of unintended impact.

Verbal permission, an inferred business relationship, or a bug-bounty
program's public scope statement does not, by itself, satisfy this
requirement unless that program's own published terms constitute such
written authorization for the specific activity performed.

This obligation exists independently of, and in addition to, any applicable
law. It reflects, among others:

- The U.S. Computer Fraud and Abuse Act (18 U.S.C. § 1030) and analogous
  state computer-crime statutes;
- Articles 323-1 to 323-3-1 of the French *Code pénal*, including the
  offense of supplying a tool "without legitimate reason" for unauthorized
  access to or interference with an automated data-processing system;
- The UK Computer Misuse Act 1990 and equivalent legislation in other
  Commonwealth jurisdictions;
- EU Directive 2013/40/EU on attacks against information systems and its
  national implementing statutes; and
- The Council of Europe Convention on Cybercrime (Budapest Convention) and
  the domestic legislation of its signatories.

This list is illustrative, not exhaustive. Computer-misuse, wiretapping,
data-protection, and critical-infrastructure statutes vary by jurisdiction
and evolve over time. The Operator alone is responsible for identifying and
complying with every law that applies to their activity, their location,
and their target's location.

## 3. Disclaimer of Warranty and Limitation of Liability

TCPCAT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE, ACCURACY, AND NON-INFRINGEMENT, AS SET OUT IN SECTION 7
OF THE APACHE LICENSE, VERSION 2.0. TO THE MAXIMUM EXTENT PERMITTED BY
APPLICABLE LAW, AND AS SET OUT IN SECTION 8 OF THAT LICENSE, IN NO EVENT
SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
LIABILITY ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR ITS
USE.

Without narrowing the foregoing, the authors and contributors accept no
liability for, and the Operator assumes all risk arising from:

- Misuse of the software, including use against systems for which
  authorization under Section 2 was not obtained;
- Collateral or unintended impact on the target environment, adjacent
  systems, or shared infrastructure (for example, saturated links, exhausted
  connection tables, or crashed services caused by scan traffic);
- Unintended denial of service resulting from timing, concurrency, or
  traffic-shaping options chosen by the Operator; and
- Violation of an internet service provider's, cloud provider's, or hosting
  provider's Acceptable Use Policy as a result of traffic the Operator
  originated with this tool.

**Assessment features do not guarantee security-control bypass.** Options
that vary packet fragmentation, timing, decoy sourcing, or other traffic
characteristics (see [`--evasion`](README.md#idsips-visibility-testing),
`--decoy`, `-T`, and related flags) exist to help an authorized team
validate what its own IDS/IPS and monitoring stack actually records under
different, realistic traffic patterns. They are visibility-testing
instruments, not a warranty:

- They do not guarantee that any control is bypassed, that detection is
  reduced, or that a target is reachable;
- Results depend on the target network, endpoint protections, monitoring
  configuration, and Operator behavior, and will vary between environments;
  and
- A version or banner match against a CVE database is a **lead requiring
  validation**, not confirmation that a vulnerability exists or is
  exploitable. False positives and false negatives should be expected.

## 4. Responsible Disclosure

Security vulnerabilities **in tcpcat itself** (as opposed to vulnerabilities
tcpcat may detect in third-party systems) must be reported privately, never
through a public GitHub issue, pull request, or discussion:

1. Open a private [GitHub Security Advisory](https://github.com/NycolazSec/tcpcat/security/advisories/new)
   for this repository, or email `security@nycolazsec.com`;
2. Include reproduction steps, affected version/commit, and, where
   applicable, a proof-of-concept sufficient to confirm the issue; and
3. Allow the maintainers a reasonable window to investigate and release a
   fix before any public disclosure.

Full scope, supported versions, and response-time targets are set out in
[SECURITY.md](SECURITY.md).

## 5. Sanctions and Export Controls

The project does not represent that use, distribution, or access to tcpcat
is compliant with the laws of every jurisdiction. Users are responsible for
complying with applicable sanctions, export-control rules, import
restrictions, and local regulations, including rules that may apply to
their organization, destination, or use case.

This notice is not legal advice and does not constitute an OFAC,
export-control, or regulatory compliance certification. Obtain qualified
legal advice when your distribution or use may be subject to sanctions or
export controls.

## 6. No Compliance Guarantee

tcpcat is provided under the Apache License 2.0. The authors do not
guarantee compliance with OFAC, EAR, GDPR, computer-misuse laws, or any
other regulation. Users remain responsible for their own legal and
operational decisions.

## 7. Contributions

Contributions must preserve this notice's authorized-use documentation and
must not intentionally add functionality whose primary purpose is
unauthorized access, disruption, credential theft, persistence, or
concealment of unlawful activity. Pull requests should include relevant
tests and documentation updates. See [CONTRIBUTING.md](CONTRIBUTING.md).
