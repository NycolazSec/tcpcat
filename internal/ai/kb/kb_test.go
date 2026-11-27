package kb

import (
	"testing"

	"github.com/NycolazSec/tcpcat/internal/ports"
)

func TestEmbeddedDictionaryIsValid(t *testing.T) {
	d, err := Parse(servicesYAML)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(d.All()); n < 80 {
		t.Fatalf("dictionary has %d services, expected the full set", n)
	}
}

func TestInheritance(t *testing.T) {
	d := Default()
	o := d.Get("openssh")
	if o == nil {
		t.Fatal("openssh missing")
	}
	if o.Exposure != Restricted || o.Why.FR == "" || o.Protocol() != "ssh" {
		t.Fatalf("openssh did not inherit from ssh: %+v", o)
	}
	if len(o.Ports) != 0 {
		t.Fatalf("ports must not be inherited, got %v", o.Ports)
	}
	m := d.Get("mysql")
	if m.Exposure != Private || m.Risk != "high" || m.Protocol() != "mysql" {
		t.Fatalf("mysql did not inherit from the database group: %+v", m)
	}
	if d.Get("database") != nil {
		t.Fatal("abstract entries must not be returned")
	}
	if tls := d.Get("mqtt-tls"); tls.IsInsecure() {
		t.Fatal("mqtt-tls overrides insecure: false")
	}
}

func TestLookups(t *testing.T) {
	d := Default()
	for name, want := range map[string]string{
		"openssh": "openssh", "ms-wbt-server": "rdp", "Microsoft-IIS": "iis",
		"microsoft-ds": "smb", "ssl/http": "https", "redis": "redis",
	} {
		if s := d.ByName(name); s == nil || s.ID != want {
			t.Errorf("ByName(%q) = %v, want %s", name, s, want)
		}
	}
	ids := func(ss []*Service) map[string]bool {
		m := map[string]bool{}
		for _, s := range ss {
			m[s.ID] = true
		}
		return m
	}
	if got := ids(d.ByPort(6379)); !got["redis"] {
		t.Errorf("port 6379: %v", got)
	}
	if got := ids(d.ByPort(2222)); !got["ethernet-ip"] {
		t.Errorf("port 2222: %v", got)
	}
	if got := ids(d.ByUDPPort(161)); !got["snmp"] {
		t.Errorf("udp 161: %v", got)
	}
}

func TestParseRejectsMistakes(t *testing.T) {
	for name, y := range map[string]string{
		"unknown field": "version: 1\nservices:\n  - id: x\n    nmae: X\n",
		"bad exposure":  "version: 1\nservices:\n  - id: x\n    name: X\n    exposure: open\n    risk: low\n    what: {en: a, fr: b}\n",
		"no why":        "version: 1\nservices:\n  - id: x\n    name: X\n    exposure: private\n    risk: low\n    what: {en: a, fr: b}\n",
		"parent loop":   "version: 1\nservices:\n  - id: a\n    parent: b\n  - id: b\n    parent: a\n",
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every port the dictionary can judge is scanned by --top-ports 200.
func TestDictionaryPortsAreInTheTopPorts(t *testing.T) {
	top := map[int]bool{}
	for _, p := range ports.GetTopPorts(200) {
		top[p] = true
	}
	for _, p := range Default().Ports() {
		if !top[p] {
			t.Errorf("port %d is in the dictionary but not in the first 200 top ports: add it to internal/ports dictionaryPorts", p)
		}
	}
}

// The Rust entries are found by their ports and carry the exposure the
// dictionary promises: the game port is public, RCON is private.
func TestRustEntriesAreLoaded(t *testing.T) {
	d := Default()
	for id, want := range map[string]struct {
		exposure string
		udp      bool
		port     int
	}{
		"rust-game": {Public, true, 28015},
		"rust-rcon": {Private, false, 28016},
	} {
		s := d.Get(id)
		if s == nil {
			t.Errorf("%s: missing from the dictionary", id)
			continue
		}
		if s.Exposure != want.exposure {
			t.Errorf("%s: exposure %q, want %q", id, s.Exposure, want.exposure)
		}
		found := false
		var matches []*Service
		if want.udp {
			matches = d.ByUDPPort(want.port)
		} else {
			matches = d.ByPort(want.port)
		}
		for _, m := range matches {
			if m.ID == id {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: port %d does not lead to it", id, want.port)
		}
	}
}
