// Package inventory lists, from inside a host, every TCP socket in LISTEN
// state together with what owns it: process, systemd unit, container,
// Kubernetes pod. `tcpcat explain` joins this inside view with an outside
// scan of the same host to say, for each reachable port, which program is
// behind it and why it is reachable.
//
// Collection reads /proc (Linux only) and needs root to see the sockets of
// every process. Nothing is sent on the network.
package inventory

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Format = "tcpcat-inventory/v1"

type Inventory struct {
	Format      string     `json:"format"`
	Hostname    string     `json:"hostname"`
	CollectedAt time.Time  `json:"collected_at"`
	Addresses   []string   `json:"addresses"`
	Listeners   []Listener `json:"listeners"`
	// Services are Kubernetes Services exposing node ports or load-balancer
	// ports (best effort, when kubectl is available).
	Services []KubeService `json:"kubernetes_services,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
}

// Listener is one listening TCP socket and its owner (when found).
type Listener struct {
	Address string `json:"address"` // local IP the socket is bound to ("0.0.0.0", "::", "127.0.0.1"...)
	Port    int    `json:"port"`
	Inode   uint64 `json:"-"`
	Owner   *Owner `json:"owner,omitempty"`
}

type Owner struct {
	PID       int    `json:"pid"`
	Process   string `json:"process"`
	Cmdline   string `json:"cmdline,omitempty"`
	Unit      string `json:"systemd_unit,omitempty"`
	Container string `json:"container_id,omitempty"`
	// ContainerName is resolved through the Docker CLI when available.
	ContainerName string `json:"container_name,omitempty"`
	PodUID        string `json:"pod_uid,omitempty"`
	Pod           string `json:"pod,omitempty"` // namespace/name, via kubectl when available
	// ForwardsTo is set for docker-proxy: the container address it relays to.
	ForwardsTo string `json:"forwards_to,omitempty"`
}

type KubeService struct {
	Name     string `json:"name"` // namespace/name
	Type     string `json:"type"`
	Port     int    `json:"port"`
	NodePort int    `json:"node_port,omitempty"`
}

// tcpListen is the st column value of a LISTEN socket in /proc/net/tcp.
const tcpListen = "0A"

// ParseProcNetTCP extracts the listening sockets from the content of
// /proc/net/tcp (ipv6=false) or /proc/net/tcp6 (ipv6=true).
func ParseProcNetTCP(data string, ipv6 bool) ([]Listener, error) {
	var out []Listener
	for i, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if i == 0 || len(fields) < 10 || fields[3] != tcpListen {
			continue
		}
		hostHex, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		ip, err := decodeProcAddr(hostHex, ipv6)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("line %d: bad port %q", i+1, portHex)
		}
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		out = append(out, Listener{Address: ip.String(), Port: int(port), Inode: inode})
	}
	return out, nil
}

// decodeProcAddr decodes the kernel's hex address: each 32-bit word is in
// host (little-endian on every platform tcpcat targets) byte order.
func decodeProcAddr(h string, ipv6 bool) (net.IP, error) {
	raw, err := hex.DecodeString(h)
	if err != nil || (ipv6 && len(raw) != 16) || (!ipv6 && len(raw) != 4) {
		return nil, fmt.Errorf("bad address %q", h)
	}
	for w := 0; w+4 <= len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	ip := net.IP(raw)
	if v4 := ip.To4(); v4 != nil && ipv6 && !strings.Contains(ip.String(), ":") {
		return v4, nil // ::ffff:a.b.c.d
	}
	return ip, nil
}

var (
	reUnit      = regexp.MustCompile(`([\w@.\-\\]+\.service)(?:/|$)`)
	reContainer = regexp.MustCompile(`(?:docker-|cri-containerd-|crio-|libpod-)?([0-9a-f]{64})(?:\.scope)?(?:/|$)`)
	rePod       = regexp.MustCompile(`pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)
)

// ParseCgroup reads the systemd unit, container ID and pod UID out of the
// content of /proc/<pid>/cgroup.
func ParseCgroup(data string) (unit, container, podUID string) {
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		if m := rePod.FindStringSubmatch(path); m != nil && podUID == "" {
			podUID = strings.ReplaceAll(m[1], "_", "-")
		}
		if m := reContainer.FindStringSubmatch(path); m != nil && container == "" {
			container = m[1]
		}
		if m := reUnit.FindStringSubmatch(path); m != nil && unit == "" && container == "" {
			unit = m[1]
		}
	}
	return unit, container, podUID
}

// dockerProxyTarget reads docker-proxy's "-container-ip X -container-port Y".
func dockerProxyTarget(args []string) string {
	var ip, port string
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "-container-ip":
			ip = args[i+1]
		case "-container-port":
			port = args[i+1]
		}
	}
	if ip == "" || port == "" {
		return ""
	}
	return net.JoinHostPort(ip, port)
}

// secretArg matches flags whose value must not be copied into an inventory.
var secretArg = regexp.MustCompile(`(?i)(pass|secret|token|key|auth|credential)`)

// RedactCmdline joins a command line, hiding secret flag values, and caps it.
func RedactCmdline(args []string) string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out); i++ {
		a := out[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		if name, _, has := strings.Cut(a, "="); has {
			if secretArg.MatchString(name) {
				out[i] = name + "=REDACTED"
			}
		} else if secretArg.MatchString(a) && i+1 < len(out) && !strings.HasPrefix(out[i+1], "-") {
			out[i+1] = "REDACTED"
			i++
		}
	}
	s := strings.Join(out, " ")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func (inv Inventory) Write(path string) error {
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

func Load(path string) (Inventory, error) {
	var inv Inventory
	data, err := os.ReadFile(path)
	if err != nil {
		return inv, fmt.Errorf("read inventory: %w", err)
	}
	if err := json.Unmarshal(data, &inv); err != nil {
		return inv, fmt.Errorf("parse inventory: %w", err)
	}
	if inv.Format != Format {
		return inv, fmt.Errorf("%s is not a tcpcat inventory (format %q)", path, inv.Format)
	}
	return inv, nil
}
