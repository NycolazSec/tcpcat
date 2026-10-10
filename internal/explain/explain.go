// Package explain joins an inside view of a host (internal/inventory: what
// listens, and who owns it) with an outside scan of it (what is reachable),
// and classifies every port:
//
//	EXPOSED    reachable, and a local process listens on it: names the
//	           process / unit / container and how to stop exposing it
//	FORWARDED  reachable, but nothing on the host listens on it: NAT,
//	           Docker/Kubernetes port mapping, a load balancer
//	SHIELDED   a process listens on every interface but the scan could not
//	           reach it: only the firewall stands between it and the network
//	REFUSED    a process listens, but connections are refused: a REJECT rule,
//	           or (Docker) a published port with nothing listening behind it
//	LOCAL      bound to loopback (or another address): not reachable, by design
//	UNTESTED   listening on a reachable address, but the scan didn't probe it
//
// A scanner alone sees the first two as "open port"; a host agent alone sees
// the first and third as "listening". Neither can tell them apart.
package explain

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/NycolazSec/tcpcat/internal/inventory"
	"github.com/NycolazSec/tcpcat/internal/scan"
)

const (
	Exposed   = "EXPOSED"
	Forwarded = "FORWARDED"
	Shielded  = "SHIELDED"
	Refused   = "REFUSED"
	Local     = "LOCAL"
	Untested  = "UNTESTED"
)

type Entry struct {
	Port      int                    `json:"port"`
	Class     string                 `json:"class"`
	Expected  bool                   `json:"expected"`
	Severity  string                 `json:"severity"`
	Listeners []string               `json:"bound_to,omitempty"`
	Owner     *inventory.Owner       `json:"owner,omitempty"`
	Service   string                 `json:"service,omitempty"` // from -sV, when the scan ran it
	Kube      *inventory.KubeService `json:"kubernetes_service,omitempty"`
	Why       string                 `json:"why"`
	Fix       string                 `json:"fix,omitempty"`
}

type Report struct {
	Host    string  `json:"host"`
	Target  string  `json:"scanned_address"`
	Entries []Entry `json:"entries"`
}

// SelectTarget picks which scanned address is this host: the one given, or
// the only scanned address that is also one of the host's own addresses.
// A host behind 1:1 NAT (most clouds) is scanned on an address it doesn't
// have, so that case needs the address given explicitly.
func SelectTarget(inv inventory.Inventory, results []scan.TargetResult, given string) (string, error) {
	scanned := map[string]bool{}
	for _, r := range results {
		scanned[r.IP] = true
	}
	if given != "" {
		if !scanned[given] {
			return "", fmt.Errorf("the scan report has no result for %s", given)
		}
		return given, nil
	}
	var matches []string
	for _, a := range inv.Addresses {
		if scanned[a] {
			matches = append(matches, a)
		}
	}
	switch {
	case len(matches) == 1:
		return matches[0], nil
	case len(matches) > 1:
		return "", fmt.Errorf("the scan covers several addresses of %s (%s): pick one with --target", inv.Hostname, strings.Join(matches, ", "))
	case len(scanned) == 1:
		for ip := range scanned {
			return "", fmt.Errorf("scanned address %s is not one of %s's addresses (NAT?): if it is this host, pass --target %s", ip, inv.Hostname, ip)
		}
	}
	return "", fmt.Errorf("none of the scanned addresses belongs to %s: pass --target <address scanned>", inv.Hostname)
}

// covers reports whether a socket bound to bound accepts connections sent
// to target. A wildcard IPv6 socket ("::") also takes IPv4 on Linux unless
// IPV6_V6ONLY is set, which is the default (net.ipv6.bindv6only=0).
func covers(bound, target string) bool {
	if bound == target {
		return true
	}
	t := net.ParseIP(target)
	switch bound {
	case "0.0.0.0":
		return t != nil && t.To4() != nil
	case "::":
		return true
	}
	return false
}

// Explain classifies every port seen from either side. expected lists the
// ports meant to be public (a web server's 80/443): they are still reported,
// but not as problems.
func Explain(inv inventory.Inventory, results []scan.TargetResult, target string, expected map[int]bool) Report {
	state := map[int]scan.TargetResult{}
	for _, r := range results {
		if r.IP == target {
			state[r.Port] = r
		}
	}

	type side struct {
		reachable []inventory.Listener // bound to target or a wildcard
		other     []inventory.Listener // loopback or another address
	}
	byPort := map[int]*side{}
	for _, l := range inv.Listeners {
		s := byPort[l.Port]
		if s == nil {
			s = &side{}
			byPort[l.Port] = s
		}
		if covers(l.Address, target) {
			s.reachable = append(s.reachable, l)
		} else {
			s.other = append(s.other, l)
		}
	}

	ports := map[int]bool{}
	for p := range byPort {
		ports[p] = true
	}
	for p, r := range state {
		if r.State == scan.StateOpen {
			ports[p] = true
		}
	}

	rep := Report{Host: inv.Hostname, Target: target}
	for port := range ports {
		r, scanned := state[port]
		open := scanned && r.State == scan.StateOpen
		s := byPort[port]
		if s == nil {
			s = &side{}
		}
		e := Entry{Port: port, Expected: expected[port], Service: r.Service}
		owned := s.reachable
		if len(owned) == 0 {
			owned = s.other
		}
		for _, l := range owned {
			e.Listeners = append(e.Listeners, l.Address)
			if e.Owner == nil && l.Owner != nil {
				e.Owner = l.Owner
			}
		}

		kube := kubeServiceFor(inv.Services, port)
		switch {
		case open && kube != nil:
			// kube-proxy / the service load balancer rewrites the destination
			// in PREROUTING, before local delivery: a process that also
			// listens on this port locally never sees external traffic.
			e.Class = Forwarded
			e.Kube = kube
			e.Why = fmt.Sprintf("reachable from the scanner through Kubernetes Service %s (%s): external connections are redirected into the cluster", kube.Name, kube.Type)
			if len(s.reachable) > 0 {
				e.Why += fmt.Sprintf("; %s also listens on %s but does not receive this traffic", ownerLabel(e.Owner), strings.Join(e.Listeners, ", "))
			}
			e.Fix = fixForwarded(kube, port)
		case open && len(s.reachable) > 0:
			e.Class = Exposed
			e.Why = fmt.Sprintf("reachable from the scanner, and %s listens on %s", ownerLabel(e.Owner), strings.Join(e.Listeners, ", "))
			e.Fix = fixExposed(e.Owner, port)
		case open:
			e.Class = Forwarded
			e.Why = "reachable from the scanner, but no process on this host listens on it for this address: the connection is forwarded"
			if len(s.other) > 0 {
				e.Why += fmt.Sprintf(" (%s listens on %s only)", ownerLabel(e.Owner), strings.Join(e.Listeners, ", "))
			}
			e.Fix = fixForwarded(e.Kube, port)
		case len(s.reachable) > 0 && scanned && r.State == scan.StateClosed:
			e.Class = Refused
			if e.Owner != nil && e.Owner.Process == "docker-proxy" {
				e.Why = fmt.Sprintf("%s publishes this port, but connections are refused: nothing listens on %s inside the container", ownerLabel(e.Owner), e.Owner.ForwardsTo)
				e.Fix = "Remove the stale port mapping, or fix the service inside the container so it listens on the published port."
			} else {
				e.Why = fmt.Sprintf("%s listens on %s, but connections are refused (a firewall REJECT rule, or a service that turns them away)", ownerLabel(e.Owner), strings.Join(e.Listeners, ", "))
				e.Fix = fixShielded(e.Owner, port)
			}
		case len(s.reachable) > 0 && scanned:
			e.Class = Shielded
			e.Why = fmt.Sprintf("%s listens on %s, but the scan found it %s: only the firewall keeps it off the network",
				ownerLabel(e.Owner), strings.Join(e.Listeners, ", "), strings.ToLower(r.State))
			e.Fix = fixShielded(e.Owner, port)
		case len(s.reachable) > 0:
			e.Class = Untested
			e.Why = fmt.Sprintf("%s listens on %s, but the scan did not probe this port", ownerLabel(e.Owner), strings.Join(e.Listeners, ", "))
			e.Fix = "Re-scan with this port included (e.g. -p 1-65535) to know whether it is reachable."
		default:
			e.Class = Local
			e.Why = fmt.Sprintf("%s listens on %s only", ownerLabel(e.Owner), strings.Join(e.Listeners, ", "))
		}
		e.Severity = severity(e)
		rep.Entries = append(rep.Entries, e)
	}

	order := map[string]int{Exposed: 0, Forwarded: 1, Shielded: 2, Refused: 3, Untested: 4, Local: 5}
	sort.Slice(rep.Entries, func(i, j int) bool {
		a, b := rep.Entries[i], rep.Entries[j]
		if a.Expected != b.Expected {
			return !a.Expected
		}
		if order[a.Class] != order[b.Class] {
			return order[a.Class] < order[b.Class]
		}
		return a.Port < b.Port
	})
	return rep
}

// Problems counts the reachable ports that were not declared as expected.
func (r Report) Problems() int {
	n := 0
	for _, e := range r.Entries {
		if (e.Class == Exposed || e.Class == Forwarded) && !e.Expected {
			n++
		}
	}
	return n
}

func severity(e Entry) string {
	sensitive := sensitivePorts[e.Port]
	switch e.Class {
	case Exposed, Forwarded:
		if e.Expected {
			return "info"
		}
		if sensitive {
			return "high"
		}
		return "medium"
	case Shielded:
		if sensitive {
			return "low"
		}
		return "info"
	}
	return "info"
}

var sensitivePorts = map[int]bool{
	21: true, 22: true, 23: true, 135: true, 139: true, 445: true, 1433: true, 1521: true,
	2375: true, 2376: true, 2379: true, 2380: true, 3306: true, 3389: true, 5000: true,
	5432: true, 5900: true, 5984: true, 6379: true, 6443: true, 8086: true, 9090: true,
	9200: true, 10250: true, 11211: true, 27017: true,
}

func ownerLabel(o *inventory.Owner) string {
	if o == nil {
		return "an unidentified process"
	}
	label := fmt.Sprintf("%s (pid %d", o.Process, o.PID)
	switch {
	case o.ContainerName != "":
		label += ", container " + o.ContainerName
	case o.Pod != "":
		label += ", pod " + o.Pod
	case o.Container != "":
		label += ", container " + o.Container[:12]
	case o.Unit != "":
		label += ", unit " + o.Unit
	}
	return label + ")"
}

func kubeServiceFor(svcs []inventory.KubeService, port int) *inventory.KubeService {
	for i := range svcs {
		if svcs[i].NodePort == port || (svcs[i].Type == "LoadBalancer" && svcs[i].Port == port) {
			return &svcs[i]
		}
	}
	return nil
}

// bindFixes are the configuration knobs that restrict a daemon to loopback.
var bindFixes = map[string]string{
	"sshd":          "set ListenAddress in /etc/ssh/sshd_config, or allow port 22 only from your admin addresses in the firewall",
	"redis-server":  "set `bind 127.0.0.1 ::1` and `protected-mode yes` in redis.conf",
	"postgres":      "set listen_addresses = 'localhost' in postgresql.conf (and tighten pg_hba.conf)",
	"mysqld":        "set bind-address = 127.0.0.1 in the [mysqld] section of my.cnf",
	"mariadbd":      "set bind-address = 127.0.0.1 in the [mysqld] section of my.cnf",
	"mongod":        "set net.bindIp: 127.0.0.1 in mongod.conf",
	"memcached":     "start it with -l 127.0.0.1",
	"dockerd":       "never expose the Docker API on TCP without TLS client auth: remove -H tcp://... or bind it to 127.0.0.1",
	"etcd":          "set --listen-client-urls to https://127.0.0.1:2379 (and require client certificates)",
	"elasticsearch": "set network.host: 127.0.0.1 in elasticsearch.yml",
	"rpcbind":       "disable rpcbind if NFS is not used (systemctl disable --now rpcbind.socket rpcbind)",
	"cupsd":         "set Listen localhost:631 in cupsd.conf",
	"node_exporter": "start it with --web.listen-address=127.0.0.1:9100 and scrape through a private network",
	"prometheus":    "start it with --web.listen-address=127.0.0.1:9090 or put it behind an authenticating proxy",
	"grafana":       "set http_addr = 127.0.0.1 in grafana.ini and serve it through your reverse proxy",
	"kubelet":       "keep the kubelet ports firewalled to the cluster network",
	"containerd":    "keep containerd's ports firewalled to the host",
	"java":          "bind the application to 127.0.0.1 (e.g. server.address=127.0.0.1 for Spring Boot) and publish it through a reverse proxy",
	"node":          "bind the server to 127.0.0.1 (e.g. app.listen(port, '127.0.0.1')) and publish it through a reverse proxy",
	"gunicorn":      "bind it to 127.0.0.1 (--bind 127.0.0.1:PORT) and publish it through a reverse proxy",
	"uvicorn":       "start it with --host 127.0.0.1 and publish it through a reverse proxy",
	"python":        "bind the application to 127.0.0.1 (e.g. --host 127.0.0.1 / --bind 127.0.0.1) and publish it through a reverse proxy",
	"nginx":         "if this port is meant to be public, pass it with --expect; otherwise restrict its `listen` directive to 127.0.0.1",
	"apache2":       "if this port is meant to be public, pass it with --expect; otherwise use `Listen 127.0.0.1:PORT`",
	"httpd":         "if this port is meant to be public, pass it with --expect; otherwise use `Listen 127.0.0.1:PORT`",
	"caddy":         "if this port is meant to be public, pass it with --expect; otherwise bind the site to 127.0.0.1",
}

func lookupBindFix(process string) (string, bool) {
	if fix, ok := bindFixes[process]; ok {
		return fix, true
	}
	if strings.HasPrefix(process, "python") {
		return bindFixes["python"], true
	}
	return "", false
}

func fixExposed(o *inventory.Owner, port int) string {
	if o == nil {
		return "Run `tcpcat inventory` as root on the host to identify the owner. If it already ran as root, the socket is held outside the host's process view (e.g. by a container runtime): check `docker ps` and `ss -ltnp`."
	}
	if o.Process == "docker-proxy" {
		name := o.ContainerName
		if name == "" {
			name = "the container"
		}
		return fmt.Sprintf("Published by Docker for %s (-> %s). Publish it on loopback only (`-p 127.0.0.1:%d:%s`, or `\"127.0.0.1:%d:...\"` in compose) or drop the port mapping if nothing outside needs it.",
			name, o.ForwardsTo, port, containerPort(o.ForwardsTo), port)
	}
	fix, known := lookupBindFix(o.Process)
	if !known {
		fix = "configure it to listen on 127.0.0.1 only, or allow this port only from the addresses that need it in the firewall"
	}
	where := ""
	switch {
	case o.Pod != "":
		where = fmt.Sprintf(" It runs in pod %s: check for hostNetwork: true or a hostPort in its spec.", o.Pod)
	case o.Unit != "":
		where = fmt.Sprintf(" Its configuration: `systemctl cat %s`.", o.Unit)
	}
	return strings.ToUpper(fix[:1]) + fix[1:] + "." + where
}

func fixForwarded(k *inventory.KubeService, port int) string {
	if k != nil && k.NodePort == port && k.Port != port {
		return fmt.Sprintf("NodePort %d of Kubernetes Service %s (%s): every node accepts it, a duplicate entry next to the Service's own port %d. Firewall the NodePort range (30000-32767), or set `allocateLoadBalancerNodePorts: false` on a LoadBalancer Service.", port, k.Name, k.Type, k.Port)
	}
	if k != nil {
		return fmt.Sprintf("Kubernetes Service %s (%s) maps this port. If it must not be public, make it ClusterIP, or set loadBalancerSourceRanges / a NetworkPolicy.", k.Name, k.Type)
	}
	return fmt.Sprintf("Find the forwarding rule: `iptables -t nat -S | grep -- '--dport %d'` or `nft list ruleset | grep %d`, `docker ps` (published ports), `kubectl get svc -A`. If the host is behind a cloud load balancer or 1:1 NAT, check its listener/security group.", port, port)
}

func fixShielded(o *inventory.Owner, port int) string {
	how := "make it listen on 127.0.0.1 only"
	// Daemon-specific knobs help here; the generic "bind the app and use a
	// reverse proxy" advice for exposed web apps doesn't add anything.
	if fix, known := lookupBindFix(processName(o)); known && !strings.Contains(fix, "reverse proxy") && !strings.Contains(fix, "--expect") {
		how += " (" + fix + ")"
	}
	return fmt.Sprintf("Defense in depth: if nothing remote needs port %d, %s, so a firewall mistake can't expose it.", port, how)
}

func processName(o *inventory.Owner) string {
	if o == nil {
		return ""
	}
	return o.Process
}

func containerPort(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return "PORT"
}
