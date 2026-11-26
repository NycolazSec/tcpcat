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
   a small trained classifier: naive Bayes over character n-grams of the
   banner, plus a separate, learned weight for the port number. It names the
   service behind a port and says how sure it is. It weighs 165 KB and
   answers in microseconds.

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

The model was trained on the 1,991 banner examples of
[Rapid7 Recog](https://github.com/rapid7/recog) (BSD-2-Clause, see
[NOTICE](../NOTICE)), plus the examples in the dictionary. Each example is
framed the way its protocol presents it: Recog's `OpenSSH_9.6` reaches tcpcat
as `SSH-2.0-OpenSSH_9.6`.

Every example is degraded under each of seven **network conditions** before
tcpcat's own sanitizer stores it:
- the whole banner;
- a banner cut by a read deadline;
- only the first bytes;
- binary noise (Telnet negotiation, framing);
- different formatting;
- a non-standard port;
- all of these at once.

The split is by fingerprint, so near-identical banners never sit on both
sides:
- 60 % train;
- 20 % calibrate the port weight and the confidence;
- 20 % are held out.

On held-out banners, the model names the right kind of service in 100 % of
cases on standard ports, under every degradation. Here it is compared with
the scanner's signatures and port fallback:

| Condition | AI | Detector alone |
|---|---:|---:|
| Clean, truncated, first bytes, noise, reformatted | 100 % | 96 % |
| Non-standard port | 91 % | 20 % |
| Truncated + noisy + non-standard port | 82 % | 16 % |

When it says it is sure (50 % or more), it is right 96 to 100 % of the time.
The full table, regenerated at each training, is in
[`internal/ai/model/EVALUATION.md`](../internal/ai/model/EVALUATION.md).

To retrain:

```bash
git clone --depth 1 https://github.com/rapid7/recog /tmp/recog
go run ./internal/ai/aitrain -recog /tmp/recog
```

## Limits

- It judges what the scan saw. A port that answered nothing identifiable
  stays "unknown", with the command to find what listens on it.
- The dictionary covers common services, not every product. An unlisted
  service is reported as such, never guessed.
- It is not a chat assistant. It explains findings and writes policies. It
  does not hold a conversation.
