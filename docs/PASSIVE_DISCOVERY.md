# Passive discovery (`tcpcat passive`)

Most of tcpcat *probes*: it sends packets and reads the replies. `tcpcat
passive` does the opposite — it **watches the kernel** and reports what the host
listens on and who it talks to, **without sending a single packet**. It is the
traffic-driven complement to the active scanner and to the `/proc`-based
`inventory` snapshot.

```bash
sudo tcpcat passive --duration 30s
```

```text
[*] Passively observing TCP activity (30s). No packets are sent.
────────────────────────────────────────────────────────────────────────────────
[*] Listening sockets observed:
    0.0.0.0:9090
[*] Connections observed:
    inbound  10.0.0.5:9090 ← 203.0.113.9:54112 (x3)
    outbound 10.0.0.5:51020 → 10.0.0.12:5432   (x1)
────────────────────────────────────────────────────────────────────────────────
[✓] 1 listening socket(s), 2 connection relationship(s) observed.
```

Add `--json` for machine-readable output, or `--duration 0` to run until
Ctrl-C.

## Why this is useful

- **Finds services a scan can't.** A port that is firewalled from your scanner,
  or only ever open briefly, never shows up in an active scan — but if it
  accepts a connection while `passive` is attached, you see it.
- **Shows real exposure.** An `inbound` connection to a local service is
  someone actually reaching it, not a theoretical open port. These are coloured
  for attention.
- **Maps east-west traffic.** `outbound` relationships reveal what a host
  depends on (databases, APIs, update servers) — useful for segmentation work
  and for spotting a host talking to something it shouldn't.
- **Zero scan footprint.** Nothing is transmitted, so it is safe to run on
  fragile or production networks where active scanning is not allowed.

## How it works

`passive` loads a tiny eBPF program and attaches it to the kernel tracepoint
`sock/inet_sock_set_state`, which fires on every TCP state transition. The
program keeps only the transitions worth reporting —

- a socket entering **LISTEN** → a service started listening, and
- a socket entering **ESTABLISHED** → a connection completed, with the previous
  state telling inbound (`SYN_RECV → ESTABLISHED`) from outbound
  (`SYN_SENT → ESTABLISHED`)

— and streams a fixed record for each through a BPF ring buffer to tcpcat, which
aggregates them into the report above. The eBPF program is written as raw eBPF
assembly (like the rest of tcpcat's engine): **no C, no clang, no kernel
headers** to build.

## Requirements and limits

- **Linux only**, kernel **≥ 5.8** (BPF ring buffer). Verified on 6.12.
- Needs **root** (or `CAP_BPF` + `CAP_PERFMON`) to load the program.
- **IPv4 only** for now; IPv6 (`AF_INET6`) is a planned follow-up.
- It observes **from the moment it attaches** — a service already listening
  before you start is seen only once it next accepts a connection. Pair it with
  `tcpcat inventory` for the point-in-time snapshot of everything already bound.
- Tracepoints are host-global: on a box running containers it observes the
  whole kernel's TCP activity, which is usually what you want for asset
  discovery.

## Roadmap

- IPv6.
- UDP flows (via a matching tracepoint/kprobe).
- Attribute each flow to its owning PID / container / cgroup.
- A continuous mode that feeds the `inventory` and segmentation features.
