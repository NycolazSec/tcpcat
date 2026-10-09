# tcpcat Examples

Practical, copy-pasteable examples. Every flag below is a real tcpcat flag —
run `tcpcat --help` for the full list, and see the main [README](../README.md)
for the complete CLI reference.

> **Authorization required.** Only scan hosts and networks you own or have
> explicit written permission to test. `scanme.nmap.org` (used below) is a
> public host Nmap provides specifically for scan testing.

## Quick scan

```bash
# Top 1000 ports, SYN scan, on an authorized host
sudo tcpcat -sS --top-ports 1000 scanme.nmap.org
```

## Service and version detection

```bash
# Detect services, versions, OS, and TLS posture on specific ports
sudo tcpcat -sV -O -p 22,80,443 scanme.nmap.org -j report.json
```

A trimmed example of the JSON this produces is in
[`sample-report.json`](sample-report.json).

## CVE correlation

`-sV` correlates detected service versions against the embedded offline
database. Add a Vulners API key for broader online coverage:

```bash
sudo tcpcat -sV -p 1-1000 --vulners-apikey "$VULNERS_API_KEY" target -j report.json
```

## Reports in multiple formats

```bash
# Every format can be requested in the same run; each writes its own file
sudo tcpcat -sV -p 443 target \
  -j report.json \
  --sarif report.sarif \
  -oX report.xml \
  -oN report.txt
```

## High-throughput scan (eBPF/AF_XDP, Linux 5.8+)

```bash
sudo tcpcat --ebpf -i eth0 -p 1-65535 -sS --open -T 5 --rate 25000 target
```

## Authorized audit with a scope file

Restrict resolved targets to an explicitly authorized list. Blank lines and
`#` comments are ignored.

```text
# scope.txt
10.42.0.0/16
app-test.example.internal
```

```bash
sudo tcpcat \
  --profile safe-production \
  --scope-file scope.txt \
  -Pn -p 443 -sV \
  -j report.json \
  --audit-log audit.jsonl \
  10.42.10.15
```

`safe-production` applies conservative timing (`-T 2`), caps the rate at 300
pps, and disables evasion, fragmentation, and decoys.

## Comparing against a baseline

Detect newly exposed ports, version changes, and new CVEs relative to a
previous tcpcat JSON report:

```bash
sudo tcpcat --profile safe-production --scope-file scope.txt \
  -Pn -p 443 -sV \
  -j report-current.json \
  --baseline report-previous.json \
  --changes changes.json \
  10.42.10.15
```

## Industrial / OT networks (gentle profile)

```bash
# Full TCP connect only, one connection at a time, 5 pps, no crafted packets
sudo tcpcat --profile ot --scope-file scope.txt 10.10.0.0/24
```

Add `--ot-probe` to read an exact vendor/version from OT ports (Modbus,
EtherNet/IP) via a single read-only query. See the main README for the risks.

## WASM detection scripts

Load a directory of sandboxed WASM detection modules written in Rust, C, Go,
or AssemblyScript:

```bash
sudo tcpcat -sV --scripts ./my-detections/ -p 1-1000 target
```

## AWS EC2 tag-based discovery

Discover and scan EC2 instances matching tags (requires AWS credentials in the
environment):

```bash
sudo tcpcat --aws-region eu-west-1 --aws-tags 'Key=App,Value=Web' -sV -p 443
```

## Local web interface

```bash
# Starts a local dashboard on 127.0.0.1:8080 by default
sudo tcpcat --web
```

Open the exact URL tcpcat prints (`http://127.0.0.1:8080/#token=…`): it carries
a per-session token, and API requests without it are rejected. Requests from
other sites or rebound host names are refused as well. Keep the default loopback
address; a non-loopback `--web-addr` serves plain HTTP to the network.

---

- For the full CLI reference and licensing, see the main [README](../README.md).
- For the Go packages, see [`internal/`](../internal/).
