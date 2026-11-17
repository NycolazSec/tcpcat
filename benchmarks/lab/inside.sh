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
MASSCAN_WAIT="${MASSCAN_WAIT:-1}"
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
  --arg masscan "$(masscan --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)" \
  --arg hyperfine "$(hyperfine --version)" \
  --arg ports "$PORTS" --arg rate "$RATE" --arg runs "$RUNS" --arg targets "${HOSTS[*]}" \
  '{kernel:$kernel, arch:$arch, cpu:$cpu, cores:($cores|tonumber), mem_kb:($mem_kb|tonumber),
    interface:$iface, nic_driver:$driver, nic_model:$nic_model, nic_speed_mbps:$nic_speed,
    nic_rx_queues:($nic_queues|tonumber), mtu:($mtu|tonumber),
    versions:{tcpcat:$tcpcat, nmap:$nmap, naabu:$naabu, masscan:$masscan, hyperfine:$hyperfine},
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
# --ebpf-copy: the lab's veth gives AF_XDP copy mode only, where tcpcat would
# otherwise switch to its raw-socket engine; this row measures AF_XDP itself.
wrapper tcpcat-ebpf "tcpcat -i $IF -p $PORTS -sS --ebpf --ebpf-copy --debug --open -T 5 --rate $RATE -Pn -j \$OUTFILE ${HOSTS[*]} >\$LOGFILE 2>&1"
wrapper tcpcat-syn  "tcpcat -i $IF -p $PORTS -sS --open -T 5 --rate $RATE -Pn -j \$OUTFILE ${HOSTS[*]} >\$LOGFILE 2>&1"
# nmap: $RATE is a ceiling (--max-rate), as it is for the other tools, and
# nmap paces itself below it with its own defaults. Forcing it up with
# --min-rate makes it miss ports at high rates, which would be measuring a
# misconfigured nmap rather than nmap.
wrapper nmap        "nmap -e $IF -p $PORTS -sS -n -Pn -T4 --max-rate $RATE -oG \$OUTFILE ${HOSTS[*]} >\$LOGFILE 2>&1"
wrapper naabu       "naabu -interface $IF -p $PORTS -rate $RATE -host $comma_hosts -silent -Pn -o \$OUTFILE >\$LOGFILE 2>&1"
# masscan sends every probe to a single next-hop MAC and does no neighbour
# lookup of its own: by default the default gateway's. On the lab's Docker
# network that would detour its probes through the host's routing (and its
# firewall rules) while every other tool reaches the targets directly. So
# one masscan per target runs side by side, aimed at that target's own MAC
# (--router-mac) when it is on-link, each at RATE/N: same path and same
# total rate ceiling as the others. A routed target keeps masscan's default
# next hop, which is then the right one. --wait is how long masscan listens
# after its last probe; its default (10 s) is sized for the Internet, and
# MASSCAN_WAIT (default 1 s) is the setting used here.
#
# masscan 1.3.2 (Debian's) intermittently never exits after its scan: its
# countdown goes negative ("waiting -538-secs") and it ignores SIGINT. A
# watchdog stops it with SIGTERM after the time its probes need at the rate,
# plus --wait, plus 15 s. Its output is lost then, so that run counts as
# invalid, and report.py says why.
probes="$(python3 -c 'import sys
n = 0
for part in sys.argv[1].split(","):
    lo, _, hi = part.partition("-")
    n += int(hi or lo) - int(lo) + 1
print(n * int(sys.argv[2]))' "$PORTS" "${#HOSTS[@]}")"
masscan_deadline=$(( probes / RATE + MASSCAN_WAIT + 16 ))
masscan_cmd=""
for i in "${!HOSTS[@]}"; do
  h="${HOSTS[$i]}"
  next_hop=""
  if [[ "$(ip route get "$h" 2>/dev/null)" != *" via "* ]]; then
    timeout 1 bash -c "exec 3<>/dev/tcp/$h/1" 2>/dev/null || true  # resolves its MAC
    mac="$(ip neigh show "$h" dev "$IF" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "lladdr") {print $(i + 1); exit}}')"
    [ -n "$mac" ] && next_hop="--router-mac $mac"
  fi
  masscan_cmd+="timeout -s TERM $masscan_deadline masscan -e $IF $next_hop -p $PORTS --rate $((RATE / ${#HOSTS[@]})) --wait $MASSCAN_WAIT -oL /tmp/bench/masscan-out.$i $h >>\$LOGFILE 2>&1 & "
done
wrapper masscan     "rm -f /tmp/bench/masscan-out.*; : >\$LOGFILE; ${masscan_cmd}wait; cat /tmp/bench/masscan-out.* >\$OUTFILE"

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
