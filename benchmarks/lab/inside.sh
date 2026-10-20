#!/usr/bin/env bash
# Runs inside the scanner container (see ../run.sh): records the environment,
# times each tool with hyperfine, keeps every run's output, and hands the
# lot to report.py, which checks each run against the ground truth.
set -euo pipefail

OUT=/results
IF="${IF:-eth0}"
PORTS="${PORTS:-1-65535}"
RATE="${RATE:-25000}"
RUNS="${RUNS:-3}"
TOOLS="${TOOLS:-tcpcat-ebpf tcpcat-syn nmap naabu}"
read -r -a HOSTS <<< "${TARGETS:?TARGETS is required}"
mkdir -p "$OUT/raw" "$OUT/logs" /tmp/bench

# --- environment -----------------------------------------------------------
cpu="$(awk -F': ' '/^model name|^Model|^Hardware/{print $2; exit}' /proc/cpuinfo)"
# NIC model from its PCI slot; a virtual interface (veth, bridge) has none.
nic_dev="$(readlink -f "/sys/class/net/$IF/device" 2>/dev/null || true)"
nic_model="$( { [ -n "$nic_dev" ] && lspci -s "$(basename "$nic_dev")" 2>/dev/null | cut -d' ' -f2-; } || true)"
nic_speed="$(cat "/sys/class/net/$IF/speed" 2>/dev/null || true)"
nic_queues="$(find "/sys/class/net/$IF/queues" -maxdepth 1 -name 'rx-*' 2>/dev/null | wc -l)"
jq -n \
  --arg kernel "$(uname -r)" --arg arch "$(uname -m)" \
  --arg cpu "${cpu:-unknown}" --arg cores "$(nproc)" \
  --arg mem_kb "$(awk '/MemTotal/{print $2}' /proc/meminfo)" \
  --arg iface "$IF" --arg driver "$(ethtool -i "$IF" 2>/dev/null | awk '/^driver/{print $2}')" \
  --arg mtu "$(cat "/sys/class/net/$IF/mtu")" \
  --arg nic_model "${nic_model:-virtual interface, no PCI device}" \
  --arg nic_speed "${nic_speed:-unknown}" --arg nic_queues "$nic_queues" \
  --arg tcpcat "$(tcpcat --version 2>/dev/null | head -1)" \
  --arg nmap "$(nmap --version | head -1)" \
  --arg naabu "$(naabu -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)" \
  --arg hyperfine "$(hyperfine --version)" \
  --arg ports "$PORTS" --arg rate "$RATE" --arg runs "$RUNS" --arg targets "${HOSTS[*]}" \
  '{kernel:$kernel, arch:$arch, cpu:$cpu, cores:($cores|tonumber), mem_kb:($mem_kb|tonumber),
    interface:$iface, nic_driver:$driver, nic_model:$nic_model, nic_speed_mbps:$nic_speed,
    nic_rx_queues:($nic_queues|tonumber), mtu:($mtu|tonumber),
    versions:{tcpcat:$tcpcat, nmap:$nmap, naabu:$naabu, hyperfine:$hyperfine},
    workload:{ports:$ports, rate_pps:($rate|tonumber), runs:($runs|tonumber), targets:($targets|split(" "))}}' \
  > "$OUT/env.json"

# --- one wrapper per tool: each run writes its own output file ----------------
# Same interface, same port range, same rate, same targets for every tool.
comma_hosts="$(IFS=,; echo "${HOSTS[*]}")"
wrapper() {  # name, command using $OUTFILE
  cat > "/tmp/bench/$1.sh" <<WRAP
#!/usr/bin/env bash
n=\$(find $OUT/raw -name '$1.*' | wc -l)
OUTFILE=$OUT/raw/$1.\$((n + 1))
LOGFILE=$OUT/logs/$1.\$((n + 1)).log
$2
WRAP
  chmod +x "/tmp/bench/$1.sh"
}
# --debug only adds a few start/stop lines, among them the AF_XDP sockets' own
# drop counters, which report.py reads back from the log.
wrapper tcpcat-ebpf "tcpcat -i $IF -p $PORTS -sS --ebpf --debug --open -T 5 --rate $RATE -Pn -j \$OUTFILE ${HOSTS[*]} >\$LOGFILE 2>&1"
wrapper tcpcat-syn  "tcpcat -i $IF -p $PORTS -sS --open -T 5 --rate $RATE -Pn -j \$OUTFILE ${HOSTS[*]} >\$LOGFILE 2>&1"
# nmap: $RATE is a ceiling (--max-rate), as it is for the other tools, and
# nmap paces itself below it with its own defaults. Forcing it up with
# --min-rate makes it miss ports at high rates, which would be measuring a
# misconfigured nmap rather than nmap.
wrapper nmap        "nmap -e $IF -p $PORTS -sS -n -Pn -T4 --max-rate $RATE -oG \$OUTFILE ${HOSTS[*]} >\$LOGFILE 2>&1"
wrapper naabu       "naabu -interface $IF -p $PORTS -rate $RATE -host $comma_hosts -silent -Pn -o \$OUTFILE >\$LOGFILE 2>&1"

# --- timing, with interface drop counters around each tool -----------------------
stat() { cat "/sys/class/net/$IF/statistics/$1" 2>/dev/null || echo 0; }
echo "tool rx_dropped tx_dropped rx_errors tx_errors" > "$OUT/drops.txt"
for tool in $TOOLS; do
  [ -x "/tmp/bench/$tool.sh" ] || { echo "unknown tool: $tool" >&2; exit 2; }
  before="$(stat rx_dropped) $(stat tx_dropped) $(stat rx_errors) $(stat tx_errors)"
  echo "== $tool ($RUNS runs)"
  hyperfine --warmup 0 --runs "$RUNS" --ignore-failure \
    --export-json "$OUT/timing.$tool.json" -n "$tool" "/tmp/bench/$tool.sh" 2>&1 | sed -n '2,6p'
  after="$(stat rx_dropped) $(stat tx_dropped) $(stat rx_errors) $(stat tx_errors)"
  # shellcheck disable=SC2086
  set -- $before $after
  echo "$tool $(($5 - $1)) $(($6 - $2)) $(($7 - $3)) $(($8 - $4))" >> "$OUT/drops.txt"
done

python3 /bench/report.py "$OUT"
