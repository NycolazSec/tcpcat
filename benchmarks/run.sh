#!/usr/bin/env bash
# Reproducible tcpcat benchmark. Needs only Docker (Linux host for real
# numbers; see README.md).
#
#   ./run.sh                          full protocol: ports 1-65535, 2 hosts, 25 000 pps, 3 runs
#   RATE=1000000 ./run.sh             same, with the rate ceiling out of the way
#   PORTS=1-10000 RUNS=1 ./run.sh     quick check of the harness
#   TOOLS="tcpcat-ebpf nmap" ./run.sh  subset of tools
#
# Through a real NIC, against machines you own (see README.md):
#   on target i (0, 1, ...):  SEED=$((1337 + i)) python3 benchmarks/lab/target.py
#   on the scanner:           BENCH_TARGETS="192.0.2.10 192.0.2.11" IF=eno1 ./benchmarks/run.sh
#
# It builds tcpcat from this checkout, starts two targets listening on a
# fixed set of ports (the ground truth), runs every tool from one scanner
# container on the same interface under the same rate ceiling, and writes
# results/<timestamp>/report.md: environment (kernel, NIC, versions),
# timings, CPU time, packets dropped, and for every run whether each open
# port was found.
set -euo pipefail
cd "$(dirname "$0")/.."

PORTS="${PORTS:-1-65535}"
RATE="${RATE:-25000}"
RUNS="${RUNS:-3}"
TOOLS="${TOOLS:-tcpcat-ebpf tcpcat-syn nmap naabu}"
OPEN_PORTS="${OPEN_PORTS:-40}"
SEED="${SEED:-1337}"
NET=tcpcat-bench
SUBNET=10.200.0.0/24
SCANNER_IP=10.200.0.2
OUT="benchmarks/results/$(date +%Y%m%d-%H%M%S)"
# BENCH_TARGETS set: the targets are other machines, each already running
# lab/target.py, and the scanner uses the host's own interface $IF.
EXTERNAL="${BENCH_TARGETS:-}"
if [ -n "$EXTERNAL" ]; then
  read -r -a TARGET_IPS <<< "$EXTERNAL"
  : "${IF:?set IF to the interface that reaches the targets (e.g. IF=eno1)}"
else
  TARGET_IPS=(10.200.0.20 10.200.0.21)
fi

cleanup() {
  docker rm -f tcpcat-bench-t0 tcpcat-bench-t1 >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
mkdir -p "$OUT"

echo "==> Building the scanner image (tcpcat from this checkout, nmap, naabu, hyperfine)"
docker build -q -f benchmarks/lab/Dockerfile -t tcpcat-bench-scanner . >/dev/null

target_ports() {  # the ports target number $1 listens on, from the seed alone
  docker run --rm -e PRINT_PORTS=1 -e SEED="$((SEED + $1))" -e COUNT="$OPEN_PORTS" \
    -v "$(pwd)/benchmarks/lab/target.py:/target.py:ro" python:3.13-slim python /target.py
}

: > "$OUT/ground_truth.txt"
if [ -n "$EXTERNAL" ]; then
  echo "==> Using ${#TARGET_IPS[@]} external target(s) through $IF: ${TARGET_IPS[*]}"
  NETWORK_ARGS=(--network host -e IF="$IF")
else
  echo "==> Starting the lab: network $SUBNET, ${#TARGET_IPS[@]} targets with $OPEN_PORTS open ports each"
  docker network create --subnet "$SUBNET" "$NET" >/dev/null
  for i in "${!TARGET_IPS[@]}"; do
    docker run -d --name "tcpcat-bench-t$i" --network "$NET" --ip "${TARGET_IPS[$i]}" \
      --ulimit nofile=65536:65536 -e SEED="$((SEED + i))" -e COUNT="$OPEN_PORTS" \
      -v "$(pwd)/benchmarks/lab/target.py:/target.py:ro" python:3.13-slim python /target.py >/dev/null
  done
  # A target prints its ports once every one of them is listening.
  for i in "${!TARGET_IPS[@]}"; do
    for _ in $(seq 1 40); do
      docker logs "tcpcat-bench-t$i" 2>/dev/null | grep -q . && break
      sleep 0.25
    done
  done
  NETWORK_ARGS=(--network "$NET" --ip "$SCANNER_IP")
fi
for i in "${!TARGET_IPS[@]}"; do
  for port in $(target_ports "$i"); do
    echo "${TARGET_IPS[$i]}:$port" >> "$OUT/ground_truth.txt"
  done
done
echo "    ground truth: $(wc -l < "$OUT/ground_truth.txt" | tr -d ' ') open ports"

echo "==> Running: ports $PORTS, $RATE pps, $RUNS run(s) per tool: $TOOLS"
# Privileged: raw sockets and the XDP hook need it. In the lab that stays
# inside the container; with BENCH_TARGETS the hook goes on the host's $IF.
docker run --rm --privileged "${NETWORK_ARGS[@]}" \
  -e TARGETS="${TARGET_IPS[*]}" -e PORTS="$PORTS" -e RATE="$RATE" -e RUNS="$RUNS" -e TOOLS="$TOOLS" \
  -v "$(pwd)/$OUT:/results" tcpcat-bench-scanner

echo
echo "==> Report: $OUT/report.md"
