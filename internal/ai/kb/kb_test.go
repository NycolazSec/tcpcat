package kb

import "testing"

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
