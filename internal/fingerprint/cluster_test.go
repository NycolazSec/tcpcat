package fingerprint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/NycolazSec/tcpcat/internal/scan"
)

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"220 mail01.corp.example.com AcmeMTA 4.2.1 ready (uptime 3612s)": "<n> <host> AcmeMTA <ver> ready (uptime <n>s)",
		"AcmeDB v7.3 session=5f2a9c11e0b3 from 10.1.2.3\r\n":             "AcmeDB v<ver> session=<hex> from <ip>",
		"hello from fe80::1:2:3 port 9":                                  "hello from <ip> port <n>",
		"   ":                                                            "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func res(ip string, port int, service, banner string) scan.TargetResult {
	return scan.TargetResult{IP: ip, Port: port, State: scan.StateOpen, Service: service, Banner: banner}
}

func TestGroup(t *testing.T) {
	results := []scan.TargetResult{
		res("10.0.0.1", 7000, "unknown", "AcmeDB v7.3 session=5f2a9c11e0b3 ready"),
		res("10.0.0.2", 7000, "unknown", "AcmeDB v7.4 session=9e0c1d2f3a4b ready"),
		res("10.0.0.2", 7001, "ssl/unknown", "AcmeDB v7.4 session=00aa11bb22cc ready"),
		res("10.0.0.3", 9999, "unknown", "something else entirely"),
		res("10.0.0.4", 22, "openssh", "SSH-2.0-OpenSSH_9.6"),                                  // recognized: ignored
		res("10.0.0.5", 7000, "unknown", ""),                                                   // no banner: ignored
		{IP: "10.0.0.6", Port: 7000, State: scan.StateClosed, Service: "unknown", Banner: "x"}, // not open
	}
	clusters := Group(results)
	if len(clusters) != 2 {
		t.Fatalf("clusters = %+v", clusters)
	}
	top := clusters[0]
	if top.Hosts != 2 || len(top.Endpoints) != 3 || fmt.Sprint(top.Ports) != "[7000 7001]" {
		t.Errorf("top cluster = %+v", top)
	}

	re, err := regexp.Compile(extractPattern(top.Suggested))
	if err != nil {
		t.Fatalf("suggested signature does not compile: %v (%s)", err, top.Suggested)
	}
	m := re.FindStringSubmatch("AcmeDB v7.5 session=0123456789ab ready")
	if len(m) < 2 || m[1] != "7.5" {
		t.Errorf("suggested %s should match a new instance and capture its version, got %v", top.Suggested, m)
	}
}

func TestExportCarriesNoAddressOrRawBanner(t *testing.T) {
	clusters := Group([]scan.TargetResult{
		res("10.9.8.7", 7000, "unknown", "AcmeDB v7.3 on db.internal.example ready"),
		res("10.9.8.6", 7000, "unknown", "AcmeDB v7.3 on db2.internal.example ready"),
	})
	path := filepath.Join(t.TempDir(), "fp.json")
	if err := Export(path, clusters); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for _, leak := range []string{"10.9.8", "internal.example"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("export leaks %q:\n%s", leak, data)
		}
	}
	if !strings.Contains(string(data), `"hosts": 2`) {
		t.Errorf("export should keep the host count:\n%s", data)
	}
}

func extractPattern(sig string) string {
	start := strings.Index(sig, "`")
	end := strings.LastIndex(sig, "`")
	return sig[start+1 : end]
}
