# IDS/IPS visibility testing (deprecated)

> **Deprecated.** These options will be removed in tcpcat 2.0. tcpcat's purpose
> is to check what your own servers expose. Hiding scan traffic from your own
> monitoring does not serve that purpose, and these options make tcpcat look
> like an attack tool to the people who should trust it. Until 2.0 they keep
> working and print a warning when used.

The deprecated options are:
- `--evasion`, `--jitter`, `--frag`, `--ttl-mode`, `--probe-ttl`,
  `--window-size`, `--source-port-mode`, `--ttl-jitter`;
- `--decoy`, `--smart-bypass` (`--spoof-agent`), `--relay-server`;
- `-sI` (idle scan);
- `--deep-inspect`, `--osi-verbosity`, `--hex-dump`, `--timing-analysis`,
  `--payload-analysis`, `--protocol-trace`.

`--decoy auto` sends probes that claim to come from 1.1.1.1, 8.8.8.8 and
9.9.9.9, the public DNS resolvers of Cloudflare, Google and Quad9. Do not use
it outside a lab you own.

## What they do

Packet variation, fragmentation, and decoy traffic can help an authorized team assess how its monitoring controls record different scan patterns. Results depend on the network, endpoint protections, IDS/IPS configuration, and operator behavior. tcpcat does not guarantee reduced detection, bypass of controls, or access to a target.

| Mode | Variation | Overhead | Recommended Use |
|------|-----------|----------|-----------------|
| **off** | Baseline traffic | 0% | Authorized inventory and fast reconnaissance |
| **light** | Limited timing and packet variation | +5% | Approved production assessments |
| **moderate** | Standard variation | +15% | Monitoring validation in controlled environments |
| **aggressive** | Extensive variation | +30% | Lab validation with an approved test plan |
| **stealthy** | High-variation profile | +50% | Controlled monitoring-validation scenarios |

## Options

```
--evasion <mode>          Coordinated packet-variation level for authorized testing:
                          • off      — baseline traffic (0% overhead)
                          • light    — limited variation (+5% latency)
                          • moderate — standard variation (+15%)
                          • aggressive — extensive variation (+30%)
                          • stealthy  — high-variation testing profile (+50%)

--jitter <0.0-1.0>        Temporal variation coefficient
                          (0.0=deterministic, 1.0=random intervals)

--frag                     Enable IPv4 fragmentation for monitoring validation

--ttl-mode <mode>         TTL mutation strategy:
                          • fixed   — static TTL value
                          • random  — per-packet randomization
                          • probe   — adaptive per-target measurement

--probe-ttl <1-255>       Probe packet TTL (default: 64)

--window-size <0-65535>   TCP advertised window (0=auto-negotiate)
                          Use only to evaluate flow-state inspection visibility

--source-port-mode        Ephemeral port allocation:
                          • fixed   — static source port
                          • random  — per-packet randomization

-g <port>                 Bind to specific source port

--decoy <ips>             Comma-separated decoy source IPs for an authorized assessment
                          (requires raw socket privileges; no bypass is guaranteed)
```


## Examples (authorized audits only)

```bash
# Conservative timing variation for an approved assessment
sudo tcpcat -Pn -sT -p 1-65535 \
  --evasion light \
  --jitter 0.3 \
  --rate 5000 \
  target

# Validate how approved monitoring controls record fragmented and decoy traffic.
# These controls do not guarantee detection avoidance or IDS/IPS bypass.
sudo tcpcat -Pn -sT -p 1-10000 \
  --evasion aggressive \
  --jitter 0.8 \
  --frag \
  --ttl-mode random \
  --window-size 512 \
  --source-port-mode random \
  --decoy 8.8.8.8,1.1.1.1 \
  target
```

