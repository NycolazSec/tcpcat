# tcpcat - Modular Security & Network Analysis Engine

<div align="center">

```
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀   ⠀⠀⢤⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡾⠿⢿⡀⠀⠀⠀⠀⣠⣶⣿⣷
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣦⣴⣿⡋⠀⠀⠈⢳⡄⠀⢠⣾⣿⠁⠈⣿⡆      tcpcat v1.0 by NycolazSec
⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⠿⠛⠉⠉⠁⠀⠀⠀⠹⡄⣿⣿⣿⠀⠀⢹⇇      Modular Security & Network Engine
⠀⠀⠀⠀⠀⣠⣾⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⣰⣏⢻⣿⣿⡆⠀⠸⣿
⠀⠀⠀⢀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣆⠹⣿⣷⠀⢘⣿
⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⠋⠉⠛⠂⠹⠿⣲⣿⣿⣧
⠀⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣿⣿⣿⣷⣾⣿⡇⢀⠀⣼⣿⣿⣿⣧
⠰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⡘⢿⣿⣿⣿
⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣷⡈⠿⢿⣿⡆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠁⢙⠛⣿⣿⣿⣿⡟⠀⡿⠀⠀⢀⣿⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣶⣤⣉⣛⠻⠇⢠⣿⣾⣿⡄⢻⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⦦⣤⣾⣿⣿⣿⣿⣆
```

</div>

**tcpcat** is a modular, high-performance network security scanner written in Go. Inspired by the flexibility and power of Nmap, `tcpcat` stands out with its experimental **eBPF/AF_XDP** engine, designed to achieve extreme scanning speeds that surpass the capabilities of traditional raw sockets.

## Philosophy

The tool was designed with a dual approach:
1.  **Familiar Ergonomics**: Adopting the popular syntax and options of Nmap (`-sS`, `-sV`, `-p`, `-iL`, `-Pn`...) for immediate adoption by security professionals.
2.  **Cutting-Edge Performance**: Integrating modern network technologies (eBPF/XDP) to push the boundaries of scanning speed on large network perimeters.

## Key Features

-   **Advanced Scan Engine**: Supports a wide range of TCP (SYN, Connect, ACK, FIN, NULL, Xmas, Window) and UDP scan techniques.
-   **Extreme Performance with eBPF/XDP**: Utilizes an `AF_XDP` engine for very high-speed packet injection and capture, directly at the network driver level (`--ebpf`).
-   **Host and Service Discovery**: Includes modules for host discovery (Ping Scan), service/version detection (`-sV`), and TCP traceroute.
-   **Flexible Targeting**: Accepts IP addresses, hostnames, CIDR notation (`192.168.1.0/24`), and IP ranges (`10.0.0.1-254`).
-   **Structured Output**: Exports results in JSON format (`-j`) for easy integration with other tools (SIEM, analysis scripts...).

## Installation

Ensure that Go (version 1.18+) is installed on your system.

```bash
# 1. Clone the repository
git clone https://github.com/user/tcpcat.git
cd tcpcat

# 2. Compile the executable
go build -o tcpcat ./cmd/tcpcat

# 3. (Optional) Install the executable in your $GOPATH/bin
go install ./cmd/tcpcat
```

> **Note** : SYN scans (`-sS`), advanced scans, and the eBPF engine (`--ebpf`) required `root` privileges to operate.

## Examples of Use

**Rapid SYN scan of the 1,000 most common ports:**
```bash
sudo ./tcpcat -sS --top-ports 1000 scanme.nmap.org
```

**Specific port scanning with version detection:**
```bash
sudo ./tcpcat -sV -p 22,80,443 192.168.1.1
```

**Host discovery on a subnet, followed by an open port scan:**
```bash
sudo ./tcpcat -sS -iL liste_cibles.txt --open
```

**UDP scan on a port range:**
```bash
sudo ./tcpcat -sU -p 53,161,500 192.168.1.0/24
```

**Ultra-fast scanning using the eBPF/XDP engine (Linux only):**
```bash
sudo ./tcpcat --ebpf -p 1-1000 10.0.0.0/8
```

**TCP traceroute to a host on port 443:**
```bash
sudo ./tcpcat --traceroute scanme.nmap.org -p 443
```

## Command-Line Options

```
COMMAND-LINE OPTIONS:
  <target>         Hostnames, IP addresses, CIDR networks
  -iL <file>       Take target list from a file
  -sn              Ping Scan - disables port scan
  -Pn              Treat all hosts as online (skip host discovery)
  -PU <port>       Port for UDP ping discovery

PORTS & SCANS:
  -p <ports>       Ports to scan (e.g., 80,443 | 1-1024)
  --top-ports <n>  Scan the n most common ports
  -sS              TCP SYN Scan (Stealth)
  -sT              TCP Connect() Scan
  -sA              TCP ACK Scan (firewall detection)
  -sW              TCP Window Scan
  -sN              TCP NULL Scan (Stealth)
  -sF              TCP FIN Scan (Stealth)
  -sX              TCP Xmas Scan (Stealth)
  -sU              UDP Port Scan
  --ebpf           Enable the experimental AF_XDP/eBPF engine (High Performance)
  --open           Show only open ports

SERVICE & OS DETECTION:
  -sV              Service version detection
  -O               Enable OS detection

EVASION & OPTIONS:
  -g <port>        Use a specific source port
  --ttl <val>      Set a custom IP Time-To-Live (TTL)
  --data-string    Append a custom ASCII payload
  --data           Append a custom HEX payload
  --traceroute     Trace the router path to the target

PERFORMANCE & OUTPUT:
  -T <0-5>         Set a timing template (higher = faster)
  -w <workers>     Number of parallel workers
  -v               Enable verbose output
  -j <file>        Export results in JSON format
```

## Avertissement

This tool is intended for educational purposes and authorized security audits. The use of tcpcat on networks without explicit permission is illegal and unethical. The author assumes no liability for misuse of this tool or for any damages that may result.

## Licence

This project is distributed under the GPL license. See the LICENSE file for more details.