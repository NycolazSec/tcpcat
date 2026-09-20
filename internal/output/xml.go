package output

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	"tcpcat/internal/scan"
)

type XMLReport struct {
	XMLName  xml.Name  `xml:"nmaprun"`
	Scanner  string    `xml:"scanner,attr"`
	Version  string    `xml:"version,attr"`
	Target   string    `xml:"target"`
	Duration string    `xml:"duration"`
	Hosts    []XMLHost `xml:"host"`
}

type XMLHost struct {
	Address string    `xml:"address"`
	Ports   []XMLPort `xml:"ports>port"`
}

// Service and Vulnerabilities are pointers rather than values because
// encoding/xml still emits an empty wrapper element for a zero struct or
// an empty nested slice -- on a scan of mostly closed ports that means a
// useless <service></service><vulnerabilities></vulnerabilities> pair on
// every single one. A nil pointer is genuinely omitted.
type XMLPort struct {
	PortID          int                 `xml:"portid,attr"`
	Protocol        string              `xml:"protocol,attr"`
	State           XMLState            `xml:"state"`
	Service         *XMLService         `xml:"service,omitempty"`
	TLS             *XMLTLS             `xml:"tls,omitempty"`
	JARM            string              `xml:"jarm,attr,omitempty"`
	HTTPPosture     *XMLHTTPPosture     `xml:"http-posture,omitempty"`
	Vulnerabilities *XMLVulnerabilities `xml:"vulnerabilities,omitempty"`
}

type XMLVulnerabilities struct {
	Items []XMLVulnerability `xml:"vulnerability"`
}

type XMLState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr,omitempty"`
}

type XMLService struct {
	Name    string `xml:"name,attr,omitempty"`
	Banner  string `xml:"product,attr,omitempty"`
	Version string `xml:"version,attr,omitempty"`
	OSType  string `xml:"ostype,attr,omitempty"`
}

type XMLTLS struct {
	Version     string `xml:"version,attr,omitempty"`
	CipherSuite string `xml:"cipher,attr,omitempty"`
	PQCGroup    string `xml:"pqc_group,attr,omitempty"`
	// No omitempty, same reasoning as TLSInfo.PQCReady in internal/service/tls.go.
	PQCReady      bool     `xml:"pqc_ready,attr"`
	CertSubject   string   `xml:"cert_subject,attr,omitempty"`
	CertIssuer    string   `xml:"cert_issuer,attr,omitempty"`
	CertExpiresAt string   `xml:"cert_expires,attr,omitempty"`
	SelfSigned    bool     `xml:"self_signed,attr,omitempty"`
	Weak          bool     `xml:"weak,attr,omitempty"`
	Warnings      []string `xml:"warning,omitempty"`
}

type XMLHTTPPosture struct {
	MissingHeaders []string `xml:"missing-header,omitempty"`
	ExposedPaths   []string `xml:"exposed-path,omitempty"`
}

type XMLVulnerability struct {
	ID       string  `xml:"id,attr"`
	CVSS     float64 `xml:"cvss,attr,omitempty"`
	Severity string  `xml:"severity,attr,omitempty"`
	Title    string  `xml:",chardata"`
}

func buildXMLPort(r scan.TargetResult) XMLPort {
	port := XMLPort{
		PortID:   r.Port,
		Protocol: "tcp",
		State:    XMLState{State: strings.ToLower(r.State), Reason: r.Reason},
	}

	if r.Service != "" || r.Banner != "" || r.Version != "" || r.OS != "" {
		port.Service = &XMLService{
			Name:    r.Service,
			Banner:  r.Banner,
			Version: r.Version,
			OSType:  r.OS,
		}
	}

	if r.JARM != nil {
		port.JARM = r.JARM.Hash
	}

	if r.TLS != nil {
		port.TLS = &XMLTLS{
			Version:       r.TLS.Version,
			CipherSuite:   r.TLS.CipherSuite,
			PQCGroup:      r.TLS.PQCGroup,
			PQCReady:      r.TLS.PQCReady,
			CertSubject:   r.TLS.CertSubject,
			CertIssuer:    r.TLS.CertIssuer,
			CertExpiresAt: r.TLS.CertExpiresAt,
			SelfSigned:    r.TLS.SelfSigned,
			Weak:          r.TLS.Weak,
			Warnings:      r.TLS.Warnings,
		}
	}

	if r.HTTPPosture != nil {
		port.HTTPPosture = &XMLHTTPPosture{
			MissingHeaders: r.HTTPPosture.MissingHeaders,
			ExposedPaths:   r.HTTPPosture.ExposedPaths,
		}
	}

	if len(r.Vulnerabilities) > 0 {
		port.Vulnerabilities = &XMLVulnerabilities{}
		for _, v := range r.Vulnerabilities {
			port.Vulnerabilities.Items = append(port.Vulnerabilities.Items, XMLVulnerability{
				ID:       v.ID,
				CVSS:     v.CVSS,
				Severity: v.Severity,
				Title:    v.Title,
			})
		}
	}

	return port
}

func ExportXML(filePath string, target string, results []scan.TargetResult, duration time.Duration) error {
	report := XMLReport{
		Scanner:  "tcpcat",
		Version:  "5.0",
		Target:   target,
		Duration: duration.Round(time.Millisecond).String(),
	}

	for _, host := range groupByIP(target, results) {
		xmlHost := XMLHost{Address: host.IP}
		for _, r := range host.Results {
			xmlHost.Ports = append(xmlHost.Ports, buildXMLPort(r))
		}
		report.Hosts = append(report.Hosts, xmlHost)
	}

	data, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("XML serialization error: %w", err)
	}

	content := append([]byte(xml.Header), data...)
	content = append(content, '\n')
	return os.WriteFile(filePath, content, 0600)
}
