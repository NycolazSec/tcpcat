package drift

import (
	"testing"
	"time"

	"github.com/NycolazSec/tcpcat/internal/inventory"
)

func inv(host string, ls ...inventory.Listener) inventory.Inventory {
	return inventory.Inventory{Hostname: host, CollectedAt: time.Now(), Listeners: ls}
}

func listen(addr string, port int, proc string) inventory.Listener {
	var o *inventory.Owner
	if proc != "" {
		o = &inventory.Owner{Process: proc}
	}
	return inventory.Listener{Address: addr, Port: port, Owner: o}
}

// find returns the change for a port, or a zero Change if the diff has none.
func find(r Report, port int) Change {
	for _, c := range r.Changes {
		if c.Port == port {
			return c
		}
	}
	return Change{}
}

func TestRebindToWildcardIsHighAndWidened(t *testing.T) {
	before := inv("h", listen("127.0.0.1", 6379, "redis-server"))
	after := inv("h", listen("0.0.0.0", 6379, "redis-server"))
	r := Diff(before, after)
	c := find(r, 6379)
	if c.Kind != Widened || c.Severity != "high" {
		t.Fatalf("6379: kind=%s severity=%s, want widened/high (%+v)", c.Kind, c.Severity, c)
	}
	if r.NewlyExposed() != 1 {
		t.Errorf("NewlyExposed()=%d, want 1", r.NewlyExposed())
	}
}

func TestNewWildcardPortAppearsHigh(t *testing.T) {
	r := Diff(inv("h"), inv("h", listen("::", 5000, "python")))
	c := find(r, 5000)
	if c.Kind != Appeared || c.Severity != "high" {
		t.Fatalf("5000: %+v, want appeared/high", c)
	}
	if c.Before != "" || c.After == "" {
		t.Errorf("appeared change should have only an After side: %+v", c)
	}
}

func TestNewLoopbackPortIsNotHigh(t *testing.T) {
	r := Diff(inv("h"), inv("h", listen("127.0.0.1", 9000, "debug")))
	if c := find(r, 9000); c.Kind != Appeared || c.Severity == "high" {
		t.Fatalf("a loopback-only new port must not be high: %+v", c)
	}
	if r.NewlyExposed() != 0 {
		t.Errorf("NewlyExposed()=%d, want 0 for a loopback-only appearance", r.NewlyExposed())
	}
}

func TestNarrowingAndDisappearingAreReassuring(t *testing.T) {
	before := inv("h", listen("0.0.0.0", 6379, "redis-server"), listen("0.0.0.0", 8080, "app"))
	after := inv("h", listen("127.0.0.1", 6379, "redis-server"))
	r := Diff(before, after)
	if c := find(r, 6379); c.Kind != Narrowed || c.Severity != "info" {
		t.Errorf("6379 should be narrowed/info: %+v", c)
	}
	if c := find(r, 8080); c.Kind != Disappeared || c.Severity != "info" {
		t.Errorf("8080 should be disappeared/info: %+v", c)
	}
	if r.NewlyExposed() != 0 {
		t.Errorf("NewlyExposed()=%d, want 0", r.NewlyExposed())
	}
}

func TestOwnerChangeOnSameBind(t *testing.T) {
	before := inv("h", listen("0.0.0.0", 8080, "nginx"))
	after := inv("h", listen("0.0.0.0", 8080, "node"))
	c := find(Diff(before, after), 8080)
	if c.Kind != OwnerChanged {
		t.Fatalf("want owner_changed on a swapped program: %+v", c)
	}
	// A new program on an externally reachable port rates a look, not just info.
	if c.Severity != "medium" {
		t.Errorf("owner change on a wildcard port: severity=%s, want medium", c.Severity)
	}
}

func TestRestartSamePortNoChange(t *testing.T) {
	// Same program, same bind, different PID (a restart) is not drift.
	before := inv("h", inventory.Listener{Address: "0.0.0.0", Port: 443, Owner: &inventory.Owner{PID: 10, Process: "nginx", Unit: "nginx.service"}})
	after := inv("h", inventory.Listener{Address: "0.0.0.0", Port: 443, Owner: &inventory.Owner{PID: 99, Process: "nginx", Unit: "nginx.service"}})
	if r := Diff(before, after); len(r.Changes) != 0 {
		t.Errorf("a restart should produce no change, got %+v", r.Changes)
	}
}

func TestHighSeverityComesFirst(t *testing.T) {
	before := inv("h", listen("0.0.0.0", 100, "a"))
	after := inv("h",
		listen("127.0.0.1", 100, "a"), // narrowed (info)
		listen("0.0.0.0", 200, "b"),   // appeared wildcard (high)
		listen("127.0.0.1", 300, "c"), // appeared loopback (medium? no: loopback appearance)
	)
	r := Diff(before, after)
	if len(r.Changes) == 0 || r.Changes[0].Severity != "high" {
		t.Fatalf("first change should be the high one: %+v", r.Changes)
	}
}
