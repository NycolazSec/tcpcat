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
- masscan and ZMap remain the reference for internet-wide, raw packets-per-
  second scanning. tcpcat's aim is a fast, *correct* scanner paired with
  exposure analysis, service/OS detection, CVE correlation, WASM scripting
  and SARIF reporting.
