package output

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tcpcat/internal/scan"
	"tcpcat/internal/service"
	"tcpcat/internal/vuln"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestExportAuditJSONLWritesOneRecord(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "audit.jsonl")
	options := AuditOptions{Profile: "safe-production", RateLimit: 300, Timing: 2}
	if err := ExportAuditJSONL(filePath, "127.0.0.1", options, nil, time.Second); err != nil {
		t.Fatalf("ExportAuditJSONL() error = %v", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil || !strings.HasSuffix(string(data), "\n") || !strings.Contains(string(data), "scan_id") || !strings.Contains(string(data), "safe-production") {
		t.Fatalf("invalid audit record: %q, error = %v", data, err)
	}
}

func TestExportSARIFIncludesCVEs(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.sarif")
	results := []scan.TargetResult{{IP: "127.0.0.1", Port: 8080, State: scan.StateOpen, Vulnerabilities: []vuln.Vulnerability{{ID: "CVE-2021-41773", Title: "Apache issue", CVSS: 7.5}}}}
	if err := ExportSARIF(filePath, results, nil); err != nil {
		t.Fatalf("ExportSARIF() error = %v", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil || !strings.Contains(string(data), `"version": "2.1.0"`) || !strings.Contains(string(data), "CVE-2021-41773") {
		t.Fatalf("invalid SARIF report: %q, error = %v", data, err)
	}
}

// TestExportSARIFValidatesAgainstSchema loads the real, published SARIF
// 2.1.0 JSON schema (testdata/sarif-2.1.0-schema.json, a verbatim copy of
// json.schemastore.org/sarif-2.1.0.json) and checks that ExportSARIF's
// output actually conforms to it -- not just that it looks plausible. This
// guards two real bugs found by this exact check: a nil `results`/`rules`
// slice serializes as JSON `null`, which the schema's `type: array`
// rejects, and `shortDescription` must be a message object ({"text":
// "..."}), not a bare string.
func TestExportSARIFValidatesAgainstSchema(t *testing.T) {
	schema, err := jsonschema.Compile("testdata/sarif-2.1.0-schema.json")
	if err != nil {
		t.Fatalf("compile SARIF schema: %v", err)
	}

	validate := func(t *testing.T, results []scan.TargetResult, summary []scan.SeveritySummaryEntry) {
		t.Helper()
		filePath := filepath.Join(t.TempDir(), "report.sarif")
		if err := ExportSARIF(filePath, results, summary); err != nil {
			t.Fatalf("ExportSARIF() error = %v", err)
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("read SARIF file: %v", err)
		}
		var doc interface{}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("SARIF output is not valid JSON: %v", err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("SARIF output does not conform to the 2.1.0 schema: %v\noutput: %s", err, data)
		}
	}

	t.Run("no results at all", func(t *testing.T) {
		validate(t, nil, nil)
	})
	t.Run("open ports, no CVEs", func(t *testing.T) {
		validate(t, []scan.TargetResult{{IP: "127.0.0.1", Port: 22, State: scan.StateOpen}}, nil)
	})
	t.Run("open port with a CVE", func(t *testing.T) {
		validate(t, []scan.TargetResult{{
			IP: "127.0.0.1", Port: 8080, State: scan.StateOpen,
			Vulnerabilities: []vuln.Vulnerability{{ID: "CVE-2021-41773", Title: "Apache issue", CVSS: 7.5}},
		}}, nil)
	})
	t.Run("with a severity summary", func(t *testing.T) {
		validate(t, []scan.TargetResult{{
			IP: "127.0.0.1", Port: 8080, State: scan.StateOpen,
			Vulnerabilities: []vuln.Vulnerability{{ID: "CVE-2021-41773", Title: "Apache issue", CVSS: 7.5, Severity: "high"}},
		}}, []scan.SeveritySummaryEntry{{Severity: "high", Count: 1, Hosts: []string{"127.0.0.1"}}})
	})
}

func sampleResults() []scan.TargetResult {
	return []scan.TargetResult{
		{Port: 22, State: scan.StateOpen, Service: "ssh", Banner: "OpenSSH_9.6"},
		{Port: 80, State: scan.StateClosed, Service: "http"},
	}
}

func checkExportedFilePerm(t *testing.T, filePath string) {
	t.Helper()
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat exported file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestExportJSON(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.json")
	if err := ExportJSON(filePath, "127.0.0.1", sampleResults(), 2*time.Second, nil, nil); err != nil {
		t.Fatalf("ExportJSON() error = %v", err)
	}
	checkExportedFilePerm(t, filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("exported file is not valid JSON: %v", err)
	}
	if report.Target != "127.0.0.1" || len(report.Results) != 2 {
		t.Errorf("got %+v, want target=127.0.0.1 with 2 results", report)
	}
}

func TestExportJSONIncludesCertificateReuse(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.json")
	reuse := []service.CertReuseGroup{{
		Fingerprint: "abc123",
		Hosts: []service.CertObservation{
			{Host: "10.0.0.1", Port: 443},
			{Host: "10.0.0.2", Port: 443, JARM: "somejarm"},
		},
	}}
	if err := ExportJSON(filePath, "10.0.0.0/24", sampleResults(), 2*time.Second, reuse, nil); err != nil {
		t.Fatalf("ExportJSON() error = %v", err)
	}

	var report JSONReport
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("exported file is not valid JSON: %v", err)
	}
	if len(report.CertificateReuse) != 1 || report.CertificateReuse[0].Fingerprint != "abc123" {
		t.Errorf("CertificateReuse = %+v, want the reuse group passed in", report.CertificateReuse)
	}
}

func TestExportGrepable(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.gnmap")
	if err := ExportGrepable(filePath, "127.0.0.1", sampleResults(), 2*time.Second); err != nil {
		t.Fatalf("ExportGrepable() error = %v", err)
	}
	checkExportedFilePerm(t, filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	content := string(data)
	for _, want := range []string{"Host: 127.0.0.1", "22/open/tcp//ssh///", "80/closed/tcp//http///"} {
		if !strings.Contains(content, want) {
			t.Errorf("grepable report missing %q:\n%s", want, content)
		}
	}
}

func TestExportNormal(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.txt")
	if err := ExportNormal(filePath, "127.0.0.1", sampleResults(), 2*time.Second); err != nil {
		t.Fatalf("ExportNormal() error = %v", err)
	}
	checkExportedFilePerm(t, filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	content := string(data)
	for _, want := range []string{"PORT", "STATE", "22/tcp", "ssh", "OpenSSH_9.6", "80/tcp"} {
		if !strings.Contains(content, want) {
			t.Errorf("normal report missing %q:\n%s", want, content)
		}
	}
}

func TestExportXML(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.xml")
	if err := ExportXML(filePath, "127.0.0.1", sampleResults(), 2*time.Second); err != nil {
		t.Fatalf("ExportXML() error = %v", err)
	}
	checkExportedFilePerm(t, filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	var report XMLReport
	if err := xml.Unmarshal(data, &report); err != nil {
		t.Fatalf("exported file is not valid XML: %v", err)
	}
	if report.Target != "127.0.0.1" || len(report.Hosts) != 1 || len(report.Hosts[0].Ports) != 2 {
		t.Fatalf("got %+v, want target=127.0.0.1 with 1 host holding 2 ports", report)
	}
	if report.Hosts[0].Ports[0].State.State != "open" {
		t.Errorf("port state = %q, want lowercased 'open'", report.Hosts[0].Ports[0].State.State)
	}
}

func TestExportXMLCarriesServiceIntelligence(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.xml")
	results := []scan.TargetResult{{
		IP: "10.0.0.1", Port: 443, State: scan.StateOpen, Service: "nginx", Version: "1.24.0", OS: "ubuntu",
		TLS: &service.TLSInfo{
			Version: "TLS 1.0", CipherSuite: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", CertSubject: "example.com",
			SelfSigned: true, Weak: true, Warnings: []string{"self-signed certificate"},
		},
		HTTPPosture: &service.HTTPPostureInfo{
			MissingHeaders: []string{"Content-Security-Policy"},
			ExposedPaths:   []string{"/.git/HEAD"},
		},
		Vulnerabilities: []vuln.Vulnerability{{ID: "CVE-2021-41773", Title: "Apache issue", CVSS: 7.5, Severity: "HIGH"}},
	}}

	if err := ExportXML(filePath, "10.0.0.1", results, time.Second); err != nil {
		t.Fatalf("ExportXML() error = %v", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}

	// The TLS/HTTP-posture/CVE findings used to be JSON-only: the XML
	// export flattened a result down to name+banner and silently dropped
	// everything -sV actually discovered.
	for _, want := range []string{
		"TLS 1.0", "self-signed certificate", "Content-Security-Policy",
		"/.git/HEAD", "CVE-2021-41773", `version="1.24.0"`, `ostype="ubuntu"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("XML report missing %q:\n%s", want, data)
		}
	}
}

// multiHostResults is two hosts with overlapping port numbers -- the shape
// that used to be exported as a single bogus host carrying everyone's ports.
func multiHostResults() []scan.TargetResult {
	return []scan.TargetResult{
		{IP: "10.0.0.1", Port: 22, State: scan.StateOpen, Service: "ssh"},
		{IP: "10.0.0.2", Port: 22, State: scan.StateOpen, Service: "ssh"},
		{IP: "10.0.0.1", Port: 443, State: scan.StateOpen, Service: "https"},
	}
}

func TestExportXMLSeparatesHosts(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.xml")
	if err := ExportXML(filePath, "10.0.0.0/24", multiHostResults(), time.Second); err != nil {
		t.Fatalf("ExportXML() error = %v", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	var report XMLReport
	if err := xml.Unmarshal(data, &report); err != nil {
		t.Fatalf("exported file is not valid XML: %v", err)
	}

	if len(report.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2 (one per scanned IP)", len(report.Hosts))
	}
	if report.Hosts[0].Address != "10.0.0.1" || len(report.Hosts[0].Ports) != 2 {
		t.Errorf("host[0] = %+v, want 10.0.0.1 with its own 2 ports", report.Hosts[0])
	}
	if report.Hosts[1].Address != "10.0.0.2" || len(report.Hosts[1].Ports) != 1 {
		t.Errorf("host[1] = %+v, want 10.0.0.2 with its own 1 port", report.Hosts[1])
	}
}

func TestExportGrepableSeparatesHosts(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.gnmap")
	if err := ExportGrepable(filePath, "10.0.0.0/24", multiHostResults(), time.Second); err != nil {
		t.Fatalf("ExportGrepable() error = %v", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	content := string(data)

	for _, want := range []string{
		"Host: 10.0.0.1 ()\tPorts: 22/open/tcp//ssh///, 443/open/tcp//https///",
		"Host: 10.0.0.2 ()\tPorts: 22/open/tcp//ssh///",
		"2 IP addresses scanned",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("grepable report missing %q:\n%s", want, content)
		}
	}
}

func TestExportNormalSeparatesHosts(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.txt")
	if err := ExportNormal(filePath, "10.0.0.0/24", multiHostResults(), time.Second); err != nil {
		t.Fatalf("ExportNormal() error = %v", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	content := string(data)
	for _, want := range []string{"Host: 10.0.0.1", "Host: 10.0.0.2"} {
		if !strings.Contains(content, want) {
			t.Errorf("normal report missing %q:\n%s", want, content)
		}
	}
}

func TestGroupByIPFallsBackToTargetAndPreservesOrder(t *testing.T) {
	// A single-target scan can leave TargetResult.IP empty; those results
	// belong to the target itself rather than to a host named "".
	hosts := groupByIP("127.0.0.1", sampleResults())
	if len(hosts) != 1 || hosts[0].IP != "127.0.0.1" || len(hosts[0].Results) != 2 {
		t.Fatalf("got %+v, want one 127.0.0.1 host holding both results", hosts)
	}

	hosts = groupByIP("10.0.0.0/24", multiHostResults())
	if len(hosts) != 2 || hosts[0].IP != "10.0.0.1" || hosts[1].IP != "10.0.0.2" {
		t.Fatalf("got %+v, want hosts in first-seen order", hosts)
	}
	if hosts[0].Results[0].Port != 22 || hosts[0].Results[1].Port != 443 {
		t.Errorf("host 10.0.0.1 ports = %+v, want them in scan order (22 then 443)", hosts[0].Results)
	}
}

func TestExportScriptKiddie(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "report.1337")
	if err := ExportScriptKiddie(filePath, "127.0.0.1", sampleResults(), 2*time.Second); err != nil {
		t.Fatalf("ExportScriptKiddie() error = %v", err)
	}
	checkExportedFilePerm(t, filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	// toLeet replaces letters with digits, so the leetspeak port line for
	// port 22 ("Port 22/tcp is open (ssh)") should no longer read plainly.
	if strings.Contains(string(data), "Port 22/tcp is open") {
		t.Errorf("expected leetspeak transformation, got plain text:\n%s", data)
	}
}

func TestToLeet(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"leet", "l337"},
		{"LEET", "L337"},
		{"Attack", "4774ck"},
		{"1234", "1234"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := toLeet(tt.in); got != tt.want {
				t.Errorf("toLeet(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
