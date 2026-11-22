# Benchmark results

tcpcat's performance claims are **only ever numbers you can reproduce with one
command**. The earlier version of this page quoted large speedups ("23.8×",
"2.62×") that came from broken measurements — a single-host run whose standard
deviation exceeded its mean, and a two-host run that in fact scanned only one
host. Those numbers are withdrawn and are not quoted anywhere anymore.

## Reproduce it yourself

Everything lives in [`benchmarks/`](../benchmarks/). One command measures
tcpcat against Nmap and naabu **and verifies every tool found every open port**
against a known ground truth — a fast run that missed a port is not counted:

```bash
./benchmarks/run.sh                 # 1-65535, 2 hosts, 25 000 pps ceiling, 3 runs/tool
RATE=1000000 ./benchmarks/run.sh    # each tool as fast as it will go
```

It needs only Docker. The report, raw output and full environment (kernel, CPU,
NIC, driver, how AF_XDP attached) are written under `benchmarks/results/`. See
[benchmarks/README.md](../benchmarks/README.md) for the method, the exact
commands compared, and the limits of each run.

## Latest run: v1.7.0 code on a Linux server

One session on 2026-11-17: a KVM server with 8 vCPUs, Linux 6.12, a veth
interface with AF_XDP in **copy mode**, 131 070 probes per run, 80 open ports,
5 runs per tool. tcpcat was the v1.7.0 development branch (raw-socket fix in,
eBPF fixes not yet). Nmap 7.93, naabu 2.7.0, masscan 1.3.2. The full story,
including what went wrong, is in
[Benchmarking port scanners honestly](https://tcpcat.io/blog/benchmarking-port-scanners-honestly).

Rate ceiling 1 000 000 packets/s (each tool as fast as it will go):

| Tool | Mean ± σ | CPU (user+sys) | Open ports, worst run | Valid |
|---|---|---|---|---|
| tcpcat -sS | 1.316 s ± 0.124 | 6.7 s | 80/80 | yes |
| nmap | 4.583 s ± 0.343 | 4.3 s | 80/80 | yes |
| tcpcat --ebpf (copy mode) | 5.385 s ± 0.187 | 9.0 s | 80/80 | yes |
| naabu | 8.622 s ± 0.203 | 40.5 s | 76/80 | **no** |
| masscan | n/a (hung in 5 of 5 runs) | n/a | 0/80 | **no** |

Rate ceiling 25 000 packets/s (no run can take less than ~5.24 s):

| Tool | Mean ± σ | CPU (user+sys) | Open ports, worst run | Valid |
|---|---|---|---|---|
| tcpcat -sS | 5.436 s ± 0.016 | 11.0 s | 80/80 | yes |
| nmap | 5.610 s ± 0.034 | 4.7 s | 80/80 | yes |
| tcpcat --ebpf (copy mode) | 5.810 s ± 0.187 | 9.2 s | 80/80 | yes |
| naabu | 17.758 s ± 0.051 | 49.6 s | 80/80 | yes |
| masscan | n/a (hung in 4 of 5 runs) | n/a | 0/80 | **no** |

### Reading this honestly

- **At full speed, tcpcat's raw-socket engine was the fastest valid tool in
  this lab**, about 3.5× faster than Nmap. That ratio belongs to this lab and
  is not a claim about your network.
- **Nmap is the most CPU-efficient tool.** If CPU is your constraint, it
  remains the better choice.
- **At a shared rate ceiling the valid tools tie at the floor**, apart from
  naabu, which is about 3× slower there and misses ports at full speed.
- **tcpcat's AF_XDP engine is slower than its raw-socket engine here.** AF_XDP
  runs in copy mode on a veth, where it has no advantage; since v1.7.0,
  `--ebpf` uses the raw-socket engine in copy mode (`--ebpf-copy` keeps
  AF_XDP). Its case rests on zero-copy NICs, not measured yet.
- **The environment caps every tool.** Traffic between the lab's containers
  crosses about 770 iptables rules (Docker, k3s, flannel) on this host, and
  the server was shared. Nmap did the same workload in 0.94 s in a laptop
  Docker lab.

## Across a real network: two servers 11 ms apart

The runs above never leave one machine: no latency, no loss. On 2026-11-22
the same protocol ran between two servers in different datacenters:

- **Scanner**: KVM server, 4 vCPUs (Haswell), Linux 6.12, otherwise idle.
- **Targets**: the two `target.py` processes (seeds 1337 and 1338, 80 open
  ports) on the other server. Round trip 10.9 ms, no ping loss.
- **Path**: a WireGuard tunnel between the two servers (MTU 1420), so the
  probes were encrypted between two machines we own rather than sent as a
  port scan across the Internet. Its encryption is part of what was measured.
- **Versions**: tcpcat 1.7.0-6-gebe92a5 (v1.7.0 scanner code), Nmap 7.93,
  naabu 2.7.0, 131 070 probes per run.
- **Not run**: `tcpcat --ebpf` (its XDP hook would have sat on a tunnel that
  carries production traffic) and masscan (it needs an Ethernet interface).

Each tool with its defaults and the rate ceiling:

| Ceiling | tcpcat -sS | nmap | naabu |
|---|---|---|---|
| 25 000 pps, 5 runs | 12.04 s ± 0.38, 80/80 | 13.46 s ± 0.37, 80/80 | 20.33 s ± 0.01, 65/80, **invalid** |
| 100 000 pps, 3 runs | 12.04 s ± 0.14, 80/80 | 13.43 s ± 0.24, 80/80 | 12.80 s ± 0.11, 60/80, **invalid** |

CPU time (user + sys) per run at 25 000 pps: tcpcat 4.1 s, Nmap 2.4 s,
naabu 20.9 s.

tcpcat with more workers (`-w`), 3 runs each:

| Ceiling | Workers | Mean ± σ | Open ports, worst run | Valid |
|---|---|---|---|---|
| 25 000 pps | 128 (default on 4 cores) | 12.52 s ± 0.11 | 80/80 | yes |
| 25 000 pps | 256 | 7.16 s ± 0.24 | 80/80 | yes |
| 25 000 pps | 512 | 5.38 s ± 0.01 | 80/80 | yes |
| 25 000 pps | 1024 | 5.37 s ± 0.00 | 80/80 | yes |
| 100 000 pps | 1024 | 3.60 s ± 0.17 | 80/80 | yes |
| 100 000 pps | 2048 | 3.51 s ± 0.10 | 78/80 | **no** |

### What this run shows

- **With its defaults, tcpcat is barely ahead of Nmap here** (1.12× at both
  ceilings). Neither gets near the 5.24 s that 25 000 pps allows: both are
  bound by latency, not by the ceiling.
- **tcpcat's limit is its own worker count.** Each worker waits for its
  probe's reply, so throughput is about workers ÷ round trip: 128 ÷ 10.9 ms is
  about 11 700 probes/s, or 11.2 s for this scan. The default (CPU cores × 32)
  takes neither `--rate` nor latency into account. With `-w 512` tcpcat
  reaches the 25 000 pps floor (5.38 s, 2.5× faster than Nmap), and with
  `-w 1024` it scans at 100 000 pps in 3.60 s (3.7× Nmap), every run valid.
- **Past what the path can carry, tcpcat loses ports.** With 2 048 workers at
  100 000 pps, 1.1 to 1.4 % of probes got no reply, even after retries. The
  interface counters show no drop, so the loss is further along the tunnel.
  In one run two open ports came back FILTERED (timeout). tcpcat 1.7.0 has
  no congestion control; Nmap has, which is why it is slower and was right
  in every run.
- **naabu missed open ports at both ceilings over this network** (65/80 and
  60/80), although it was valid at 25 000 pps in the Docker lab.
- **All three tools work over a WireGuard interface**, which has no Ethernet
  header: the setup of a pentest through a VPN.

### The fix: an adaptive probe window (v1.8.0)

Those findings led to a congestion window for raw scans when `-w` is not
given: it starts at the old default, grows while probes are answered on their
first attempt, stops growing when the round trip rises above twice the
fastest one seen (a queue building), and drops to 70% when a reply needed a
retransmission. Same path, same protocol, the build of PR #75 against
v1.7.0's code (`main` at ebe92a5) and Nmap in one session, 5 runs each:

| Ceiling | tcpcat 1.7.0 | tcpcat, adaptive window | Nmap |
|---|---|---|---|
| 25 000 pps | 11.95 s ± 0.33, 80/80 | **5.38 s ± 0.01**, 80/80 | 13.35 s ± 0.12, 80/80 |
| 100 000 pps | 12.07 s ± 0.25, 80/80 | **3.75 s ± 0.31**, 80/80 | 13.38 s ± 0.14, 80/80 |

With its defaults, tcpcat is now 2.5× faster than Nmap at 25 000 pps (at the
5.24 s floor) and 3.6× at 100 000 pps, about as fast as the best hand-picked
`-w` above, with every run valid. At 100 000 pps the window peaked near
1 000 probes in flight and fewer than 1% of replies needed a retransmission.
In the Docker lab the same build matched v1.7.0 (1.30 s at 1 000 000 pps,
5.45 s vs 5.39 s at 25 000 pps): with no queue to find, there is nothing to
gain there.

### Earlier sample: laptop, before v1.7.0

Docker Desktop on an Apple-silicon Mac, 10 cores, veth, copy mode. Kept for
comparison; tcpcat's raw-socket engine has used about 5× less CPU per probe
since v1.7.0.

| Ceiling | nmap | tcpcat-ebpf | tcpcat-syn | naabu |
|---|---|---|---|---|
| 25 000 pps | 5.383 s | 5.808 s | 6.325 s | 18.939 s |
| 1 000 000 pps | 0.942 s | 2.128 s | 6.560 s | 9.410 s (68/80, invalid) |

## What tcpcat does not claim

- No speed ratio without the environment it was measured in, and none from a
  run that is not reproducible with `benchmarks/run.sh`.
- No figure for AF_XDP on a zero-copy NIC until someone has measured one
  (see issue #70).
- No speed ratio over a real network beyond the ones measured above, on one
  path 11 ms long: v1.7.0's defaults were 1.12× Nmap there, and the adaptive
  window 2.5 to 3.6×. Another path, with other latency, loss or bottleneck,
  will give other numbers.
- masscan and ZMap remain the reference for internet-wide, raw packets-per-
  second scanning. tcpcat's aim is a fast, *correct* scanner paired with
  exposure analysis, service/OS detection, CVE correlation, WASM scripting
  and SARIF reporting.
