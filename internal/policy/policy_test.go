package policy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

const samplePolicy = `
version: 1
name: PCI segmentation
zones:
  servers: [10.0.20.0/30]
  shop: [shop.example.com]
rules:
  - name: guests reach no server
    from: guest-wifi
    to: servers
    ports: "22,80,443,3306"
  - from: internet
    to: shop
    ports: "1-1024"
    allow: [443/tcp, "80"]
    require: [443]
`

func fakeResolve(entries []string) ([]string, error) {
	var out []string
	for _, e := range entries {
		switch e {
		case "10.0.20.0/30":
			out = append(out, "10.0.20.1", "10.0.20.2")
		case "shop.example.com":
			out = append(out, "203.0.113.10")
		default:
			out = append(out, e)
		}
	}
	return out, nil
}

func TestParseAndPlan(t *testing.T) {
	p, err := Parse([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := strings.Join(p.Vantages(), ","); got != "guest-wifi,internet" {
		t.Errorf("Vantages = %q", got)
	}
	if p.Rules[1].Name != "internet -> shop" {
		t.Errorf("default rule name = %q", p.Rules[1].Name)
	}

	checks, err := p.Plan("internet", fakeResolve)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(checks) != 1 || len(checks[0].Targets) != 1 || len(checks[0].Ports) != 1024 {
		t.Fatalf("Plan(internet) = %+v", checks)
	}

	checks, _ = p.Plan("guest-wifi", fakeResolve)
	if len(checks) != 1 || len(checks[0].Targets) != 2 || len(checks[0].Ports) != 4 {
		t.Fatalf("Plan(guest-wifi) = %+v", checks)
	}
	if checks, _ := p.Plan("nowhere", fakeResolve); len(checks) != 0 {
		t.Errorf("Plan(nowhere) should be empty, got %d", len(checks))
	}
}

func TestParseRejectsMistakes(t *testing.T) {
	cases := map[string]string{
		"typo key":      "version: 1\nrules:\n  - from: a\n    to: b\n    alow: [443]\n",
		"bad version":   "version: 2\nrules:\n  - from: a\n    to: b\n",
		"no rules":      "version: 1\n",
		"missing to":    "version: 1\nrules:\n  - from: a\n",
		"udp allow":     "version: 1\nrules:\n  - from: a\n    to: b\n    allow: [53/udp]\n",
		"bad port":      "version: 1\nrules:\n  - from: a\n    to: b\n    allow: [99999]\n",
		"bad top":       "version: 1\nrules:\n  - from: a\n    to: b\n    ports: top-x\n",
		"empty zone":    "version: 1\nzones:\n  z: []\nrules:\n  - from: a\n    to: z\n",
		"not yaml list": "version: 1\nrules: nope\n",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestEvaluate(t *testing.T) {
	p, _ := Parse([]byte(samplePolicy))

	internet, _ := p.Plan("internet", fakeResolve)
	ok := NewCheckResult(internet[0], []Endpoint{{IP: "203.0.113.10", Port: 443}, {IP: "203.0.113.10", Port: 80}})
	if ok.Status != StatusPass || len(ok.Violations) != 0 {
		t.Errorf("allowed ports should pass: %+v", ok)
	}

	bad := NewCheckResult(internet[0], []Endpoint{{IP: "203.0.113.10", Port: 22}})
	if bad.Status != StatusFail || len(bad.Violations) != 2 {
		t.Fatalf("expected SSH open + 443 missing, got %+v", bad.Violations)
	}
	if bad.Violations[0].Kind != ViolationUnexpectedOpen || bad.Violations[0].Port != 22 {
		t.Errorf("first violation = %+v", bad.Violations[0])
	}
	if bad.Violations[1].Kind != ViolationRequiredClosed || bad.Violations[1].Port != 443 {
		t.Errorf("second violation = %+v", bad.Violations[1])
	}

	guest, _ := p.Plan("guest-wifi", fakeResolve)
	if res := NewCheckResult(guest[0], nil); res.Status != StatusPass || res.Open == nil {
		t.Errorf("nothing reachable should pass with a non-nil open list: %+v", res)
	}
}

func TestReportRoundTripSARIFAndMatrix(t *testing.T) {
	p, _ := Parse([]byte(samplePolicy))
	guest, _ := p.Plan("guest-wifi", fakeResolve)
	rep := Report{Policy: p.Name, Vantage: "guest-wifi"}
	rep.Checks = append(rep.Checks, NewCheckResult(guest[0], []Endpoint{{IP: "10.0.20.2", Port: 3306}}))
	rep.Finalize()
	if rep.Status != StatusFail {
		t.Fatalf("report status = %s", rep.Status)
	}

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "r.json")
	if err := rep.WriteJSON(jsonPath); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(jsonPath)
	if err != nil || loaded.Checks[0].Violations[0].Port != 3306 {
		t.Fatalf("LoadReport = %+v, %v", loaded, err)
	}
	if err := rep.WriteSARIF(filepath.Join(dir, "r.sarif")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	PrintMatrix(&buf, []Report{loaded})
	if !strings.Contains(buf.String(), "FAIL") || !strings.Contains(buf.String(), "OPEN 10.0.20.2:3306") {
		t.Errorf("matrix output:\n%s", buf.String())
	}
}

func TestSlug(t *testing.T) {
	if got := slug("Guests reach NO server!"); got != "guests-reach-no-server" {
		t.Errorf("slug = %q", got)
	}
}
