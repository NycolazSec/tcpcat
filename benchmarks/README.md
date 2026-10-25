# Reproducible benchmark

One command measures tcpcat against Nmap and naabu and checks that each of
them found every open port. It needs only Docker.

```bash
./benchmarks/run.sh                 # ports 1-65535, 2 hosts, ceiling 25 000 packets/s, 3 runs per tool
RATE=1000000 ./benchmarks/run.sh    # same, with the rate ceiling out of the way
PORTS=1-10000 RUNS=1 ./benchmarks/run.sh   # one-minute check that the harness works
SUBNET_PREFIX=10.211.55 ./benchmarks/run.sh # use another /24 if 10.200.0.x is taken
```

The report is written to `benchmarks/results/<timestamp>/report.md`, next to
every tool's raw output and logs.

## What a run does

1. Builds tcpcat from your checkout into an image that also holds Nmap, naabu
   and hyperfine.
2. Starts two targets on a private Docker network. Each listens on 40 TCP
   ports drawn from a fixed seed (8 well-known ones, 32 anywhere in 1-65535).
   Every other port is closed. This list is the **ground truth**.
3. Runs each tool three times from one scanner container, timed by hyperfine,
   on the same interface and under the same rate ceiling.
4. Compares every run's open ports with the ground truth and writes the report.

## The commands being compared

`$RATE` is a ceiling for every tool, and each one paces itself below it.

| Name | Command |
|---|---|
| `tcpcat-ebpf` | `tcpcat -i eth0 -p 1-65535 -sS --ebpf --debug --open -T 5 --rate $RATE -Pn -j out.json <host1> <host2>` |
| `tcpcat-syn` | `tcpcat -i eth0 -p 1-65535 -sS --open -T 5 --rate $RATE -Pn -j out.json <host1> <host2>` |
| `nmap` | `nmap -e eth0 -p 1-65535 -sS -n -Pn -T4 --max-rate $RATE -oG out.txt <host1> <host2>` |
| `naabu` | `naabu -interface eth0 -p 1-65535 -rate $RATE -host <host1>,<host2> -silent -Pn -o out.txt` |

Two choices are worth knowing about:

- Nmap gets `--max-rate` and its own defaults, not `--min-rate`. Forced to
  100 000 packets/s with `--min-rate`, Nmap found 21 of the 80 open ports in
  our lab, which measures a misconfigured Nmap rather than Nmap.
- `--debug` on `tcpcat-ebpf` adds a few start and stop lines, among them the
  AF_XDP sockets' drop counters that the report reads back.

## What the report records

- **Environment**: kernel and architecture, CPU, cores, memory; the interface,
  its driver, the NIC model (from its PCI slot), link speed and RX queues;
  how tcpcat's AF_XDP engine attached (native or generic hook, zero-copy or
  copy mode); the version of every tool.
- **Timing**: mean, standard deviation, minimum and maximum over the runs,
  plus user and system CPU time.
- **Accuracy**: open ports found in the tool's worst run, and false positives.
- **Packets dropped**: the interface's drop and error counters over the tool's
  runs, plus the replies tcpcat's AF_XDP sockets report as dropped by the
  kernel, as a count and as a share of the probes sent.

A tool is **valid** only if every one of its runs found every open port with
no false positive. Speed ratios are computed between valid tools only: a fast
run that missed a port is not a result.

## Through a real NIC

The Docker lab runs over virtual interfaces (veth), where AF_XDP works in copy
mode and there is no latency. It checks correctness and reproduces a result
anywhere, but it says little about a physical network card. For that, use two
or three Linux machines **you own**:

```bash
# on each target, numbered from 0 (needs python3 only)
SEED=$((1337 + 0)) python3 benchmarks/lab/target.py     # first target
SEED=$((1337 + 1)) python3 benchmarks/lab/target.py     # second target

# on the scanner
BENCH_TARGETS="192.0.2.10 192.0.2.11" IF=eno1 ./benchmarks/run.sh
```

The scanner container then uses the host's network and attaches tcpcat's XDP
hook to `$IF` for the duration of the `tcpcat-ebpf` runs. Run it from a
console or a second interface if `$IF` also carries your SSH session, and
check that nothing between the machines (a firewall, a cloud provider's
anti-scan filter) drops the probes. The ground truth is derived from the same
seeds, so the targets must be started with the `SEED` values above and no
other service may listen on them in the scanned range.

## Sample report

Docker Desktop on an Apple-silicon Mac: kernel 6.12.76-linuxkit (aarch64),
10 cores, veth interface, AF_XDP in copy mode, Nmap 7.93, naabu 2.6.1, tcpcat
built from the commit that added this folder. 131 070 probes per run, 80 open
ports.

Rate ceiling 25 000 packets/s (no run can take less than 5.24 s):

| Tool | Mean ± σ | CPU (user + system) | Open ports found | Dropped | Valid |
|---|---|---|---|---|---|
| nmap | 5.383 s ± 0.031 | 2.7 s | 80/80 | 0 | yes |
| tcpcat-ebpf | 5.808 s ± 0.722 | 6.3 s | 80/80 | 0 | yes |
| tcpcat-syn | 6.325 s ± 0.102 | 42.3 s | 80/80 | 0 | yes |
| naabu | 18.939 s ± 0.390 | 51.5 s | 80/80 | 0 | yes |

Rate ceiling 1 000 000 packets/s (each tool as fast as it will go):

| Tool | Mean ± σ | CPU (user + system) | Open ports found | Dropped | Valid |
|---|---|---|---|---|---|
| nmap | 0.942 s ± 0.082 | 0.9 s | 80/80 | 0 | yes |
| tcpcat-ebpf | 2.128 s ± 0.218 | 3.4 s | 80/80 | 0 | yes |
| tcpcat-syn | 6.560 s ± 0.167 | 43.2 s | 80/80 | 0 | yes |
| naabu | 9.410 s ± 0.101 | 55.0 s | 68/80 | 0 | **no** |

In this lab Nmap is the fastest tool: 1.08× faster than `tcpcat-ebpf` under
the 25 000 packets/s ceiling and 2.26× faster without it. `tcpcat-ebpf` is
3.1× faster than tcpcat's own raw-socket SYN scan for a twelfth of the CPU
time, and 3.3× faster than naabu at 25 000 packets/s.

These numbers describe a virtual interface on a laptop. They are published as
an example of the report, not as tcpcat's performance on a network card.

## Limits

- Two targets on the scanner's own network: no routing, no latency, no loss
  on the path. A scan across the Internet is dominated by those, not by the
  scanner's engine.
- Closed ports answer with a reset, so every probe gets a reply. Targets
  behind a firewall that drops probes exercise the retry and timeout logic
  instead, which this protocol does not measure.
- Three runs per tool give a mean and a spread, not a distribution. Raise
  `RUNS` before quoting a small difference.
- The `Dropped` column adds tcpcat's own AF_XDP socket counters to the
  interface counters. The other tools expose no such counter, so a reply they
  lose in a socket buffer does not appear there: the accuracy column is what
  catches it.

## Publishing a result

`benchmarks/results/` is ignored by git. To publish a run, keep its
`report.md` and `summary.json` together and quote the report's environment
section with any figure taken from it.
