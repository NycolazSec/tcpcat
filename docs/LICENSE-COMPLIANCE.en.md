# License compliance: finding and handling an undeclared integration

[Version française](LICENSE-COMPLIANCE.md)

> **Template, not legal advice.** The letters below follow the logic of the
> AGPL-3.0 / OEM dual license. Have your lawyer review them before sending, as
> with `COMMERCIAL-LICENSE.md`.

## 1. What is a violation, and what is not

| Situation | License required? |
|---|---|
| A company uses tcpcat **internally** (pentest, audit of its own or its authorized clients' networks) | **No.** The AGPL allows it, commercial use included. |
| A company **modifies** tcpcat and uses it internally | No. |
| A company **distributes** tcpcat (alone, or inside a product, appliance, image or VM) without releasing its source under the AGPL | **Yes**: OEM license, or AGPL compliance. |
| A company offers (modified) tcpcat to third parties **over a network** without publishing its changes | **Yes** (AGPL s.13): OEM license, or publish the source. |

The trigger is **distribution** or **service to third parties**, never the mere
presence of tcpcat on a network: a tcpcat scan seen in logs proves no violation.

## 2. Spotting tcpcat in a distributed product

Only on artifacts you are entitled to examine: a product you bought, a firmware or
image the vendor published, a package you downloaded.

```bash
scripts/find-tcpcat.sh extracted-firmware/    # directory (files > 100 KB)
scripts/find-tcpcat.sh ./suspect-binary       # a single file
```

Exit status: `0` nothing found, `1` indicators found. The script looks for **strong**
indicators specific to this project: the Go module path
(`github.com/NycolazSec/tcpcat`, kept in the build info even in a stripped binary),
the license notice (`tcpcat.io/oem`), and the option help texts (`--license`,
`--update`, `--web`).

Limits to keep in mind:
- A vendor who **rebuilds with a different module name and different strings** evades
  the script. It catches the common cases; it is not proof of absence.
- A hit is a **lead**: verify by hand (`go version -m <file>`, `strings`, a run in an
  isolated environment) before writing to anyone.
- Version matters: up to `v1.4.1`, tcpcat is under **Apache 2.0**, which allows
  proprietary redistribution. Compare the version found with `v1.4.1`.
  (`--version` shows the binary's version; the build info shows the module version.)

## 3. Building the file

Before any letter, keep: the examined file and its hash (`shasum -a 256`), the script
output, the source (download URL, date), the identified version, and the evidence of
distribution or of an offer of service to third parties.

## 4. Procedure

1. **Compliance letter** (template A), cordial in tone: many cases are oversights.
   Allow **30 days**.
2. Two acceptable outcomes: they **publish their source** under the AGPL, or they
   **take the commercial license** (tier by company size, see `/oem`).
3. No answer: **follow-up** (template B), then a lawyer.

**Why 30 days:** AGPL-3.0 s.8 provides that an infringer's license is permanently
reinstated if they receive a first notice and cure the violation within 30 days. The
letter must therefore be a **clear notice**: it sets the starting point and avoids
any dispute.

### Template A: compliance notice (first letter)

> **Subject: tcpcat: license compliance (AGPL-3.0): [Product]**
>
> Hello,
>
> I am Nicolas Blondelle, author and copyright holder of the tcpcat software
> (https://github.com/NycolazSec/tcpcat).
>
> While examining [product / version / date / source], I found tcpcat [version X]
> present: [indicators observed]. The product is [distributed / offered as a service
> to third parties] and I could find neither a publication of the corresponding source
> code nor an associated commercial license.
>
> tcpcat is released under the AGPL-3.0, with a commercial (OEM) license for
> integration into a proprietary product (https://tcpcat.io/oem). You can come into
> compliance in two ways:
> 1. publish the complete corresponding source code of [product] under the AGPL-3.0; or
> 2. purchase a commercial license (tiers and terms: https://tcpcat.io/oem).
>
> Please reply **within 30 days** of receiving this message, telling me which option
> you choose. I am happy to discuss it.
>
> This message constitutes notice of violation under section 8 of the AGPL-3.0.
> All rights reserved.
>
> Regards,
> Nicolas Blondelle (NycolazSec), support@tcpcat.io

### Template B: follow-up / formal notice (to be validated by a lawyer)

> **Subject: tcpcat: second notice: [Product]**
>
> Further to my letter of [date], which has gone unanswered / unresolved to date, I
> inform you that continuing to distribute [product] containing tcpcat without
> complying with the AGPL-3.0 or holding a commercial license infringes my copyright.
>
> I ask that, **within [15] days**, you [stop distribution] or come into compliance
> through one of the two options in my previous message. Failing that, I reserve the
> right to take any appropriate action, in particular under articles L. 122-6 and
> L. 335-3 of the French Intellectual Property Code [adapt to the recipient's
> jurisdiction with your lawyer].
>
> [Signature] [registered letter / e-mail with acknowledgement of receipt]

### Template C: audit (customers under a commercial license)

Section 4 of the contract (`COMMERCIAL-LICENSE.md`) provides for distribution records
and an audit on reasonable written notice.

> **Subject: tcpcat license no. [key]: compliance verification request**
>
> Under article 4 of our commercial license agreement, please send me, within [30]
> days, the record of distributions of [product] containing tcpcat since [date]
> (volumes, versions, tier). A document-based audit can be arranged on a date of your
> choice within [60] days.
>
> Nicolas Blondelle, support@tcpcat.io

## 5. Good to know

- You alone hold the rights to your code (sole human author of the repository), which
  lets you enforce the AGPL **and** sell the commercial license.
- If outside contributors add code, get a copyright assignment or license agreement
  (CLA) **before** merging: otherwise you can no longer relicense that code.
- This guide relies on no marking of network packets: since internal use is legal, the
  presence of tcpcat on a network proves nothing.
