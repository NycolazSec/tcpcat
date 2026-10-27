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

## Sample report (virtual interface, laptop)

Docker Desktop on an Apple-silicon Mac, kernel 6.12 (aarch64), 10 cores, a
veth interface with AF_XDP in **copy mode**. 131 070 probes per run, 80 open
ports. This is a *correctness and reproducibility* example, **not** tcpcat's
performance on a real network card.

Rate ceiling 25 000 packets/s (no run can physically take less than ~5.24 s):

| Tool | Mean ± σ | CPU (user+sys) | Open ports | Valid |
|---|---|---|---|---|
| nmap | 5.383 s ± 0.031 | 2.7 s | 80/80 | yes |
| tcpcat-ebpf | 5.808 s ± 0.722 | 6.3 s | 80/80 | yes |
| tcpcat-syn | 6.325 s ± 0.102 | 42.3 s | 80/80 | yes |
| naabu | 18.939 s ± 0.390 | 51.5 s | 80/80 | yes |

Rate ceiling 1 000 000 packets/s (uncapped):

| Tool | Mean ± σ | CPU (user+sys) | Open ports | Valid |
|---|---|---|---|---|
| nmap | 0.942 s ± 0.082 | 0.9 s | 80/80 | yes |
| tcpcat-ebpf | 2.128 s ± 0.218 | 3.4 s | 80/80 | yes |
| tcpcat-syn | 6.560 s ± 0.167 | 43.2 s | 80/80 | yes |
| naabu | 9.410 s ± 0.101 | 55.0 s | 68/80 | **no** |

### Reading this honestly

- **On a laptop's veth interface, Nmap is the fastest tool here.** AF_XDP runs
  in copy mode over virtual interfaces, so the kernel-bypass advantage is
  largely neutralised; Nmap is extremely well tuned for a single host.
- Where tcpcat's engine already shows is **CPU efficiency**: `tcpcat-ebpf`
  does the same work as its own raw-socket SYN scan (`tcpcat-syn`) in a small
  fraction of the CPU time, and beats naabu on both time and accuracy.
- The kernel-bypass advantage is expected to grow on a **physical NIC** in
  native / zero-copy mode. That result has to be measured on real hardware you
  own — see "Through a real NIC" in
  [benchmarks/README.md](../benchmarks/README.md) — and will be published here
  only once reproduced, never estimated.

## What tcpcat does not claim

- No "X× faster than Nmap" headline. On the numbers we can reproduce today,
  that claim would be false on a laptop and unmeasured on real hardware.
- masscan and ZMap remain the reference for internet-wide, raw packets-per-
  second scanning. tcpcat's aim is a kernel-bypass engine **paired with**
  service/OS detection, CVE correlation, WASM scripting and SARIF reporting —
  not to win a pps drag race.
