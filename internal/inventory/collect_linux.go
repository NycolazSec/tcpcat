//go:build linux

package inventory

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Collect builds the inventory of this host.
func Collect() (Inventory, error) {
	host, _ := os.Hostname()
	inv := Inventory{Format: Format, Hostname: host, CollectedAt: time.Now().UTC()}

	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				inv.Addresses = append(inv.Addresses, ipnet.IP.String())
			}
		}
	}

	for _, src := range []struct {
		path string
		v6   bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		data, err := os.ReadFile(src.path)
		if err != nil {
			if src.v6 && os.IsNotExist(err) {
				continue // IPv6 disabled
			}
			return inv, fmt.Errorf("read %s: %w", src.path, err)
		}
		listeners, err := ParseProcNetTCP(string(data), src.v6)
		if err != nil {
			return inv, fmt.Errorf("parse %s: %w", src.path, err)
		}
		inv.Listeners = append(inv.Listeners, listeners...)
	}

	owners := socketOwners()
	if os.Geteuid() != 0 {
		inv.Warnings = append(inv.Warnings, "not running as root: sockets of other users' processes have no owner")
	}
	for i := range inv.Listeners {
		inv.Listeners[i].Owner = owners[inv.Listeners[i].Inode]
	}
	enrichDocker(&inv)
	enrichKubernetes(&inv)
	return inv, nil
}

// socketOwners maps socket inodes to the process holding them, by walking
// /proc/<pid>/fd. The first process found wins (a forked server's children
// share its listening socket).
func socketOwners() map[uint64]*Owner {
	owners := map[uint64]*Owner{}
	procs, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range procs {
		pid, err := strconv.Atoi(filepath.Base(dir))
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		var owner *Owner
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err != nil {
				continue
			}
			if _, seen := owners[inode]; seen {
				continue
			}
			if owner == nil {
				owner = describeProcess(pid, dir)
			}
			owners[inode] = owner
		}
	}
	return owners
}

func describeProcess(pid int, dir string) *Owner {
	o := &Owner{PID: pid}
	if comm, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		o.Process = strings.TrimSpace(string(comm))
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		o.Cmdline = RedactCmdline(args)
		if o.Process == "docker-proxy" {
			o.ForwardsTo = dockerProxyTarget(args)
		}
	}
	if cg, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		o.Unit, o.Container, o.PodUID = ParseCgroup(string(cg))
	}
	return o
}

// run executes a fixed helper command with a timeout; any failure just
// means that enrichment is skipped.
func run(name string, args ...string) (string, bool) {
	if _, err := exec.LookPath(name); err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output() // #nosec G204 -- fixed binaries and arguments
	if err != nil {
		return "", false
	}
	return string(out), true
}

// enrichDocker names containers, and attributes docker-proxy listeners to
// the container whose published port they serve.
func enrichDocker(inv *Inventory) {
	out, ok := run("docker", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.Ports}}")
	if !ok {
		return
	}
	names := map[string]string{}
	published := map[int]string{} // host port -> container name
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		cols := strings.SplitN(line, "\t", 3)
		if len(cols) < 2 {
			continue
		}
		names[cols[0]] = cols[1]
		if len(cols) == 3 {
			for _, port := range PublishedHostPorts(cols[2]) {
				published[port] = cols[1]
			}
		}
	}
	for i := range inv.Listeners {
		o := inv.Listeners[i].Owner
		if o == nil {
			continue
		}
		if o.Container != "" && o.ContainerName == "" {
			o.ContainerName = names[o.Container]
		}
		if o.Process == "docker-proxy" && o.ContainerName == "" {
			o.ContainerName = published[inv.Listeners[i].Port]
		}
	}
}

// enrichKubernetes names pods and lists Services that expose node ports or
// load-balancer ports (traffic to those is forwarded, with no local listener).
func enrichKubernetes(inv *Inventory) {
	if _, err := os.Stat("/etc/rancher/k3s/k3s.yaml"); err == nil && os.Getenv("KUBECONFIG") == "" {
		_ = os.Setenv("KUBECONFIG", "/etc/rancher/k3s/k3s.yaml")
	}
	pods, ok := run("kubectl", "get", "pods", "-A", "-o",
		`jsonpath={range .items[*]}{.metadata.uid}{"\t"}{.metadata.namespace}/{.metadata.name}{"\n"}{end}`)
	if !ok {
		return
	}
	byUID := map[string]string{}
	for _, line := range strings.Split(pods, "\n") {
		if uid, name, ok := strings.Cut(line, "\t"); ok {
			byUID[uid] = name
		}
	}
	for i := range inv.Listeners {
		if o := inv.Listeners[i].Owner; o != nil && o.PodUID != "" {
			o.Pod = byUID[o.PodUID]
		}
	}
	svcs, ok := run("kubectl", "get", "svc", "-A", "-o",
		`jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{.spec.type}{"\t"}{range .spec.ports[*]}{.port}:{.nodePort},{end}{"\n"}{end}`)
	if ok {
		inv.Services = ParseKubeServices(svcs)
	}
}
