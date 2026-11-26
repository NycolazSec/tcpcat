# tcpcat's AI

tcpcat's AI reads a scan and tells you, in plain English or French, what is
exposed, how serious it is, why, and what to do. It runs **offline, inside the
binary**: no account, no API key, and nothing about your network leaves your
machine.

```bash
sudo tcpcat -sV --ai 203.0.113.10                # judge a scan as it finishes
tcpcat -sV -j scan.json 203.0.113.10             # or keep the scan...
tcpcat ai explain scan.json --lang fr            # ...and judge it later, in French
tcpcat ai policy scan.json -o exposure.yaml      # draft the exposure policy
tcpcat ai identify "SSH-2.0-OpenSSH_9.6" --port 2222
tcpcat ai model                                  # what it knows, how it was trained
```

`tcpcat ai explain` exits `1` when something should be fixed, so it can gate a
CI job.

## What it says

Each open port becomes one finding with a **verdict**:

- **to fix** (`fix`): it should not be reachable from where the scan ran, or
  it has a serious or actively exploited vulnerability;
- **to review** (`review`): acceptable when limited or hardened, like SSH on
  the internet, or something it could not identify;
- **as expected** (`ok`): a website, a game server, a VPN endpoint.

A finding also has a severity, a title, a **why**, a **fix**, and the
**evidence** it rests on. The rule is simple: no statement without evidence
from the scan. When a service is identified by its port number alone, the
finding says so. When several services share that port, it says which ones,
and the severity is capped at medium.

The verdict depends on **where the scan ran from**. A database reachable from
the internet must be fixed; the same database reachable from inside the
network is expected. The default vantage is `internal` when every scanned
address is private, and `internet` otherwise. Change it with `--from` (or with
`--ai-from` on a scan).

## Thorough analysis (`--ai-deep`)

The quick analysis judges what the scan saw. The thorough one takes the time
a careful administrator would:

```bash
sudo tcpcat -sV --ai-deep 203.0.113.10       # scan, then analyse in depth
tcpcat ai explain scan.json --deep           # or analyse a saved scan in depth
```

1. **It verifies its hypotheses** with read-only follow-up probes on the
   ports that were open. A probe asks what any client may ask and never sends
   a credential:
   - SSH: which login methods are offered, so it can tell whether bots can
     guess passwords. It also lists the weak algorithms and gives the exact
     `sshd_config` lines to remove them. Pterodactyl's SFTP is the exception:
     players log in there with their panel password by design, so the advice
     changes.
   - The kubelet and the Kubernetes API: does it answer anonymous requests?
   - The Docker API, Elasticsearch and Redis: does it answer without
     authentication?
   - An alternate web port: is it Pterodactyl Wings? Wings answers with its
     own error message.
   - Port 80: does it redirect to HTTPS?
   - Certificates: self-signed, expiring, or Traefik's default certificate.

   When a probe gets no answer, the finding says so ("could not be verified:
   nothing answered in SSH") instead of reading like a verified one.
2. **It works out what the machine is** from everything that answered, for
   example: "a web server, under Kubernetes (k3s), behind the Traefik reverse
   proxy, on Debian 12".
3. **It says what is fine**, for example that none of the sensitive ports it
   tested is reachable, or that TLS 1.3 is used with a post-quantum key
   exchange.
4. **It ends with a plan**, ordered by severity, with the exact command or
   setting for each step. The plan also covers patterns across ports, such
   as three SSH entry points facing the internet.

While it works, a spinner shows what it is doing and for how long. The
spinner is drawn only on a terminal, so a pipe or a CI log gets plain lines.

The thorough analysis contacts the scanned hosts again, a few seconds per
port. The SSH check leaves one failed login by user `tcpcat` in the server's
log, with no password sent. Run it only against hosts you are allowed to
scan.

## How the scan went, and what blocks it

Both analyses start with how the scan went, host by host. A port that does
not answer is not one fact but several: the machine said it is closed (a
reset), a firewall threw the packet away (no answer), a firewall refused it
out loud (an ICMP error), or something accepted the connection and then
said nothing. Read together, they say what filters the machine:
- a firewall that lets only the open ports through and drops the rest (the
  right setup);
- no firewall in front of the closed ports;
- a firewall with ports left open to nothing (maybe forgotten rules);
- a firewall that rejects instead of dropping;
- open ports answering close to the timeout, so "filtered" ports may only be
  slow (`-T2` waits longer).

It also says when the scan cannot be trusted:
- **every port tested is filtered**: the machine is off, or it ignores the
  scanner's address. Closed sensitive ports are then not reported as good
  news;
- **every open port accepts connections, but no service answers**: something
  on the path (an anti-DDoS, a SYN proxy) may be answering for the machine;
- **the scan runs from a Kubernetes node**: the cluster's firewall may trust
  that node, so cluster ports found open are "to be confirmed" from outside
  the cluster rather than critical.

The thorough analysis (`--ai-deep`) then checks this on the network,
read-only, before verifying anything else:
1. It connects again to the ports that were open. If none answers any more,
   the machine or its protection (fail2ban, CrowdSec, an anti-DDoS) blocked
   the scanner's address during the scan.
2. It waits 15 seconds and tries again. An answer means a temporary limit
   set off by the pace of the scan (scan more slowly, or allow-list the
   scanner); no answer means a ban.
3. On a host where everything was filtered, it tries a few common ports one
   slow connection at a time. An answer means it was the pace that got
   blocked.
4. On a silent open port, it waits up to 8 seconds for the service to
   speak. A banner that comes late is reported with its delay (for SSH:
   `UseDNS`, `MaxStartups`, or an anti-DDoS holding connections back) and
   then used to identify the service. A server that should speak first and
   never does is reported too.

These checks add up to about 30 seconds on a blocked host, and nothing on a
normal one beyond one connection per open port.

## How it works

The AI has three parts.

1. **The dictionary** ([`internal/ai/kb/services.yaml`](../internal/ai/kb/services.yaml)).
   It covers about a hundred network services, from SSH, Redis and the
   Kubernetes API to Minecraft, Pterodactyl Wings and Modbus. For each one it
   records:
   - what the service is;
   - whether it belongs on the internet (`public`, `restricted` or `private`);
   - how serious exposing it is;
   - why;
   - how to stop it, in English and French.

   Products inherit from their protocol (`openssh` from `ssh`), and groups
   share their text (every database has the same "why"). The file is
   reviewed like code: its statements are shown to users as the reasons
   behind a finding.

2. **The banner model** ([`internal/ai/model`](../internal/ai/model)). This is
   a small trained classifier with two parts:
   - a logistic regression over the banner: its character n-grams, its
     words, its first characters and its shape (`SSH-2.0-` around any
     product);
   - a table of the ports each service was seen on, with a weight fitted on
     held-out data: how much a port number says once the banner has spoken.

   It names the service behind a port and says how sure it is. It weighs
   375 KB and answers in microseconds.

3. **The reasoning** ([`internal/ai/ai.go`](../internal/ai/ai.go)). It joins
   the scan, the dictionary and the model:
   - A protocol probe's answer comes first, because the probe spoke the
     protocol.
   - The model reading the banner comes next.
   - The dictionary's port conventions come last.
   - A generic answer is narrowed down by the port: SSH on 2022 is
     Pterodactyl's SFTP.
   - Vulnerabilities raise the verdict. Those in CISA's catalog of exploited
     flaws become critical. Flaws of a product's client programs (OpenSSH's
     `ssh`, `scp`, `sftp`) are left out, because they do not make a server
     vulnerable.
   - A port that answers far faster than the rest of its host is flagged as
     answered by something on the network path (a home router's FTP helper,
     a transparent proxy), not by the host.

## Training under network conditions

The model learns from four sources:
- the 2,097 banner examples of
  [Rapid7 Recog](https://github.com/rapid7/recog) (BSD-2-Clause, see
  [NOTICE](../NOTICE)), each framed the way its protocol presents it: Recog's
  `OpenSSH_9.6` reaches tcpcat as `SSH-2.0-OpenSSH_9.6`, a MySQL error as the
  packet that carries it;
- about 7,300 banners generated from the patterns of Recog's fingerprints:
  new versions, hostnames and free text around what each pattern fixes, so
  the model learns what identifies the software rather than one example's
  version number;
- the examples in the dictionary;
- binary noise, as examples of a service the dictionary does not know.

Every example is degraded under each of nine **network conditions** before
tcpcat's own sanitizer stores it:
- the whole banner;
- a banner cut by a read deadline;
- only the first bytes;
- binary noise (Telnet negotiation, framing);
- different formatting;
- a non-standard port;
- a rebranded banner: the product name replaced (a custom SSH version
  string, an SMTP greeting with only the hostname);
- a server that keeps talking in the same read (the SSH key exchange right
  after the banner, a legal notice before the FTP greeting);
- truncated, noisy and on a non-standard port at once.

During training, a random 70 % of each banner's features are hidden at
every pass (dropout), so the model cannot rely on one memorized detail. An
L1 penalty removes the weights that do not help, which keeps the model
small.

The split is by fingerprint, so near-identical banners never sit on both
sides:
- 60 % train (and only these fingerprints feed the generator);
- 20 % stop the training, and calibrate the port weight and the confidence.
  The training settings were also chosen on this part;
- 20 % are held out: only real banners, judged once.

Results on held-out banners, compared with the previous model (naive Bayes,
tcpcat 1.9.0) and with the scanner's signatures and port fallback, on the
same banners:

| Condition | AI | Previous model | Detector alone |
|---|---:|---:|---:|
| Standard port: clean, truncated, first bytes, noise, reformatted | 100 % | 99.8 to 100 % | 96 % |
| Server keeps talking after the banner | 100 % | 97.4 % | 96 % |
| Rebranded banner | 99.6 % | 100 % | 96 % |
| Non-standard port | 95.7 % | 87.2 % | 21 % |
| Truncated + noisy + non-standard port | 91.1 % | 79.9 % | 16 % |

It also names the exact product more often: 98.9 % instead of 96.5 % on a
clean banner, and 92.9 % instead of 79.4 % on a non-standard port. When it
says it is sure (50 % or more), it is right 98.8 to 100 % of the time.
The full table, regenerated at each training, is in
[`internal/ai/model/EVALUATION.md`](../internal/ai/model/EVALUATION.md).

To retrain:

```bash
git clone --depth 1 https://github.com/rapid7/recog /tmp/recog
go run ./internal/ai/aitrain -recog /tmp/recog
```

Training takes about 15 seconds. To change the training settings (`-l1`,
`-dropout`, `-generate`...) without looking at the test split:

```bash
go run ./internal/ai/aitrain -recog /tmp/recog -sweep -out /dev/null -report /dev/null
go run ./internal/ai/aitrain -recog /tmp/recog -confusion unusual-port -out /dev/null -report /dev/null
```

`-sweep` prints the accuracy on the calibration split, and `-confusion`
prints the mistakes made there under one condition.

## Limits

- It judges what the scan saw. A port that answered nothing identifiable
  stays "unknown", with the command to find what listens on it.
- The dictionary covers common services, not every product. An unlisted
  service is reported as such, never guessed.
- It is not a chat assistant. It explains findings and writes policies. It
  does not hold a conversation.
