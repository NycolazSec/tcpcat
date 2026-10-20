"""Turns one benchmark run's raw files into report.md.

For every tool and *every* run, the open ports it reported are compared with
the ground truth (ground_truth.txt, one ip:port per line): a fast run that
missed ports is not a valid run, and says so in the table.
"""
import glob
import json
import re
import sys
from pathlib import Path

out = Path(sys.argv[1])
env = json.loads(out.joinpath("env.json").read_text())


def scanned(spec: str) -> set[int]:
    """Ports covered by a "1-1024,8080" specification."""
    ports = set()
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        ports |= set(range(int(lo), int(hi or lo) + 1))
    return ports


# Only open ports inside the scanned range can be found: a quick run over
# 1-10000 is judged on the ground truth of that range.
in_range = scanned(env["workload"]["ports"])
truth = {e for e in out.joinpath("ground_truth.txt").read_text().split() if int(e.rsplit(":", 1)[1]) in in_range}


def found_in(tool: str, path: str) -> set[str]:
    text = Path(path).read_text(errors="replace")
    if tool.startswith("tcpcat"):
        try:
            results = json.loads(text).get("results") or []
        except json.JSONDecodeError:
            return set()
        return {f"{r['ip']}:{r['port']}" for r in results if str(r.get("state", "")).upper() == "OPEN"}
    if tool == "nmap":  # grepable: Host: <ip> ()  Ports: 22/open/tcp//ssh///, ...
        found = set()
        for line in text.splitlines():
            m = re.match(r"Host: (\S+).*Ports: (.*)", line)
            if m:
                found |= {f"{m.group(1)}:{p.split('/')[0]}" for p in m.group(2).split(", ") if "/open/" in p}
        return found
    return {line.strip() for line in text.splitlines() if re.fullmatch(r"\S+:\d+", line.strip())}  # naabu: ip:port


drops = {}
for line in out.joinpath("drops.txt").read_text().splitlines()[1:]:
    tool, *vals = line.split()
    drops[tool] = sum(int(v) for v in vals)



def socket_drops(tool: str) -> int:
    """Replies the kernel dropped before tcpcat's AF_XDP sockets could read
    them, summed over the tool's runs (tcpcat --debug prints them on exit)."""
    total = 0
    for log in glob.glob(str(out / "logs" / f"{tool}.*.log")):
        total += sum(int(n) for n in re.findall(r"dropped by the kernel: (\d+)", Path(log).read_text(errors="replace")))
    return total


probes_per_run = len(in_range) * len(env["workload"]["targets"])
rows = []
for timing_file in sorted(glob.glob(str(out / "timing.*.json"))):
    r = json.loads(Path(timing_file).read_text())["results"][0]
    tool = r["command"]
    runs = sorted(glob.glob(str(out / "raw" / f"{tool}.*")), key=lambda p: int(p.rsplit(".", 1)[1]))
    per_run = [found_in(tool, p) for p in runs]
    missed = [len(truth - f) for f in per_run] or [len(truth)]
    false_pos = [len(f - truth) for f in per_run] or [0]
    rows.append({
        "tool": tool, "mean": r["mean"], "stddev": r.get("stddev") or 0.0, "min": r["min"], "max": r["max"],
        "user": r["user"], "system": r["system"], "runs": len(per_run),
        "worst_missed": max(missed), "worst_false_pos": max(false_pos),
        "drops": drops.get(tool, 0) + socket_drops(tool),
        "loss_pct": 100.0 * (drops.get(tool, 0) + socket_drops(tool)) / max(1, probes_per_run * max(1, len(per_run))),
        "valid": max(missed) == 0 and max(false_pos) == 0 and len(per_run) == env["workload"]["runs"],
    })

json.dump({"env": env, "ground_truth_ports": len(truth), "results": rows}, open(out / "summary.json", "w"), indent=2)

# How tcpcat's AF_XDP engine attached (native or generic hook, zero-copy or
# copy mode): the same code is several times faster on a NIC with zero-copy.
xdp_mode = "not run"
for log in sorted(glob.glob(str(out / "logs" / "tcpcat-ebpf.*.log"))):
    m = re.search(r"AF_XDP engine ready: ([^\n]*?)\.?\n", Path(log).read_text(errors="replace"))
    if m:
        xdp_mode = m.group(1)
        break

w = env["workload"]
lines = [
    "# tcpcat benchmark report", "",
    "## Environment", "",
    f"- Kernel: `{env['kernel']}` ({env['arch']}), {env['cores']} cores, {env['mem_kb'] // 1024} MiB RAM",
    f"- CPU: {env['cpu']}",
    f"- Interface: `{env['interface']}`, driver **{env['nic_driver'] or 'unknown'}**, {env['nic_model']}, "
    f"link speed {env['nic_speed_mbps']} Mb/s, {env['nic_rx_queues']} RX queue(s), MTU {env['mtu']}",
    f"- tcpcat AF_XDP engine: {xdp_mode}",
    f"- Versions: {env['versions']['tcpcat']} · {env['versions']['nmap']} · naabu {env['versions']['naabu']} · {env['versions']['hyperfine']}",
    "", "## Workload", "",
    f"- SYN scan of ports `{w['ports']}` on {len(w['targets'])} host(s) ({', '.join(w['targets'])}), "
    f"rate ceiling {w['rate_pps']} packets/s, {w['runs']} run(s) per tool, same interface for all",
    f"- Ground truth: **{len(truth)} open ports** in the scanned range (fixed seed), everything else closed",
    "", "## Results", "",
    "| Tool | Mean ± σ | Min … max | User CPU | System CPU | Open ports found (worst run) | False positives | Packets dropped (loss) | Valid |",
    "|---|---|---|---|---|---|---|---|---|",
]
for r in sorted(rows, key=lambda r: r["mean"]):
    found = len(truth) - r["worst_missed"]
    lines.append(
        f"| {r['tool']} | {r['mean']:.3f} s ± {r['stddev']:.3f} | {r['min']:.3f} … {r['max']:.3f} s | "
        f"{r['user']:.2f} s | {r['system']:.2f} s | {found}/{len(truth)} | {r['worst_false_pos']} | {r['drops']} ({r['loss_pct']:.3f} %) | "
        f"{'yes' if r['valid'] else '**NO**'} |")
valid = [r for r in rows if r["valid"]]
lines += ["", "A run is **valid** only if it found every open port of the ground truth, with no false positive, "
          "in every one of its runs. Speed ratios are computed between valid tools only.", "",
          f"Packets dropped: the scanner interface's drop and error counters over the tool's runs, plus, for "
          f"tcpcat-ebpf, the replies its AF_XDP sockets report as dropped by the kernel. The loss rate is that "
          f"count over the probes sent ({probes_per_run} per run).", ""]
base = next((r for r in valid if r["tool"] == "tcpcat-ebpf"), None)
if base:
    for r in valid:
        if r is not base:
            ratio = r["mean"] / base["mean"]
            if 0.98 <= ratio <= 1.02:
                verdict = "on par with"  # within 2 %: not a difference worth a ratio
            else:
                verdict = f"{ratio:.2f}× faster than" if ratio > 1 else f"{1 / ratio:.2f}× slower than"
            lines.append(f"- tcpcat-ebpf is **{verdict}** {r['tool']} "
                         f"(CPU time {base['user'] + base['system']:.1f} s vs {r['user'] + r['system']:.1f} s)")
elif rows:
    lines.append("- tcpcat-ebpf did not produce a valid run here, so no speed ratio is reported.")
out.joinpath("report.md").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
