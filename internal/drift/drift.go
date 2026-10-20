// Package drift compares two inventories of the same host taken at different
// times and reports how its exposure changed: a port that started listening,
// one that stopped, one that widened from loopback to every interface, and
// the program behind a port changing. It answers the question a quarterly
// audit cannot -- "what opened up since last time?" -- by diffing two
// `tcpcat inventory` snapshots. It reads the two files only; nothing is sent
// on the network.
package drift

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/NycolazSec/tcpcat/internal/inventory"
)

const Format = "tcpcat-drift/v1"

// Kind is what happened to a port between the two snapshots.
type Kind string

const (
	// Appeared: a socket now listens where none did. High when it is bound
	// to every interface.
	Appeared Kind = "appeared"
	// Disappeared: a socket that used to listen is gone.
	Disappeared Kind = "disappeared"
	// Widened: the port already listened, but its reach grew -- the usual
	// case is a service rebinding from 127.0.0.1 to 0.0.0.0, newly reachable
	// from outside after a config change or an update.
	Widened Kind = "widened"
	// Narrowed: the reverse of Widened; the port pulled back toward loopback.
	Narrowed Kind = "narrowed"
	// OwnerChanged: the port listens as before, but a different program owns
	// it now (an update, a redeploy -- or something that should not be there).
	OwnerChanged Kind = "owner_changed"
)

// Change is one port's difference between the snapshots.
type Change struct {
	Kind     Kind   `json:"kind"`
	Port     int    `json:"port"`
	Severity string `json:"severity"` // high | medium | info
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
	Note     string `json:"note"`
}

// Report is the full diff, newly exposed ports first.
type Report struct {
	Format  string    `json:"format"`
	Host    string    `json:"host"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Changes []Change  `json:"changes"`
}

// NewlyExposed counts the changes that made the host more reachable from
// outside (a new wildcard port, or one that widened to wildcard): the ones
// an operator must look at. It is what a CI gate keys on.
func (r Report) NewlyExposed() int {
	n := 0
	for _, c := range r.Changes {
		if c.Severity == "high" {
			n++
		}
	}
	return n
}

// reach is how far a bind address lets the socket be reached: 2 any
// interface, 1 one specific interface, 0 loopback only.
func reach(addr string) int {
	switch addr {
	case "0.0.0.0", "::", "":
		return 2
	}
	if ip := net.ParseIP(addr); ip != nil && ip.IsLoopback() {
		return 0
	}
	return 1
}

func reachWord(level int) string {
	switch level {
	case 2:
		return "every interface"
	case 0:
		return "loopback only"
	default:
		return "one interface"
	}
}

// portView is a port folded across its listeners in one snapshot: the widest
// reach any of them has, the address that reaches furthest, and its owner.
type portView struct {
	reach int
	addr  string
	owner *inventory.Owner
}

func fold(listeners []inventory.Listener) map[int]portView {
	byPort := map[int]portView{}
	for i := range listeners {
		l := listeners[i]
		r := reach(l.Address)
		if cur, ok := byPort[l.Port]; !ok || r > cur.reach {
			byPort[l.Port] = portView{reach: r, addr: l.Address, owner: l.Owner}
		}
	}
	return byPort
}

func ownerName(o *inventory.Owner) string {
	if o == nil {
		return ""
	}
	switch {
	case o.ContainerName != "":
		return o.Process + " in " + o.ContainerName
	case o.Pod != "":
		return o.Process + " in pod " + o.Pod
	case o.Unit != "":
		return o.Process + " (" + o.Unit + ")"
	default:
		return o.Process
	}
}

// ownerIdentity is the part of an owner used to decide "same program or
// not": the process name and, when known, its unit/container/pod. The PID
// changes on every restart, so it is deliberately left out.
func ownerIdentity(o *inventory.Owner) string {
	if o == nil {
		return ""
	}
	return o.Process + "\x00" + o.Unit + "\x00" + o.Container + "\x00" + o.Pod
}

func describe(level int, addr string, o *inventory.Owner) string {
	s := fmt.Sprintf("%s (%s)", addr, reachWord(level))
	if name := ownerName(o); name != "" {
		s += " — " + name
	}
	return s
}

// Diff compares before (the earlier snapshot) with after and returns the
// changes. Both should be inventories of the same host; Diff does not check
// that, so the caller decides what comparing two hosts would mean.
func Diff(before, after inventory.Inventory) Report {
	old, cur := fold(before.Listeners), fold(after.Listeners)
	var changes []Change

	for port, a := range cur {
		b, existed := old[port]
		switch {
		case !existed:
			sev := "medium"
			note := fmt.Sprintf("a service now listens on %s", reachWord(a.reach))
			if a.reach == 2 {
				sev = "high"
				note = "a service now listens on every interface — reachable from outside"
			}
			changes = append(changes, Change{
				Kind: Appeared, Port: port, Severity: sev,
				After: describe(a.reach, a.addr, a.owner), Note: note,
			})
		case a.reach > b.reach:
			sev := "medium"
			if a.reach == 2 {
				sev = "high"
			}
			changes = append(changes, Change{
				Kind: Widened, Port: port, Severity: sev,
				Before: describe(b.reach, b.addr, b.owner),
				After:  describe(a.reach, a.addr, a.owner),
				Note:   fmt.Sprintf("reach widened from %s to %s", reachWord(b.reach), reachWord(a.reach)),
			})
		case a.reach < b.reach:
			changes = append(changes, Change{
				Kind: Narrowed, Port: port, Severity: "info",
				Before: describe(b.reach, b.addr, b.owner),
				After:  describe(a.reach, a.addr, a.owner),
				Note:   fmt.Sprintf("reach narrowed from %s to %s", reachWord(b.reach), reachWord(a.reach)),
			})
		case ownerIdentity(a.owner) != ownerIdentity(b.owner):
			sev := "info"
			if a.reach == 2 {
				sev = "medium" // a changed program on an externally reachable port is worth a look
			}
			changes = append(changes, Change{
				Kind: OwnerChanged, Port: port, Severity: sev,
				Before: describe(b.reach, b.addr, b.owner),
				After:  describe(a.reach, a.addr, a.owner),
				Note:   "a different program owns this port now",
			})
		}
	}

	for port, b := range old {
		if _, ok := cur[port]; !ok {
			changes = append(changes, Change{
				Kind: Disappeared, Port: port, Severity: "info",
				Before: describe(b.reach, b.addr, b.owner),
				Note:   "no longer listening",
			})
		}
	}

	rank := map[string]int{"high": 0, "medium": 1, "info": 2}
	sort.SliceStable(changes, func(i, j int) bool {
		if rank[changes[i].Severity] != rank[changes[j].Severity] {
			return rank[changes[i].Severity] < rank[changes[j].Severity]
		}
		return changes[i].Port < changes[j].Port
	})

	return Report{
		Format: Format, Host: after.Hostname,
		From: before.CollectedAt, To: after.CollectedAt,
		Changes: changes,
	}
}
