// internal/output/xml.go
package output

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings" // Import manquant
	"time"

	"tcpcat/internal/scan"
)

type XMLReport struct {
	XMLName  xml.Name   `xml:"nmaprun"`
	Scanner  string     `xml:"scanner,attr"`
	Version  string     `xml:"version,attr"`
	Target   string     `xml:"target"`
	Duration string     `xml:"duration"`
	Host     XMLHost    `xml:"host"`
}

type XMLHost struct {
	Address string    `xml:"address"`
	Ports   []XMLPort `xml:"ports>port"`
}

type XMLPort struct {
	PortID   int        `xml:"portid,attr"`
	Protocol string     `xml:"protocol,attr"`
	State    XMLState   `xml:"state"`
	Service  XMLService `xml:"service"`
}

type XMLState struct {
	State string `xml:"state,attr"`
}

type XMLService struct {
	Name   string `xml:"name,attr,omitempty"`
	Banner string `xml:"product,attr,omitempty"`
}

// ExportXML écrit les résultats au format XML (-oX).
func ExportXML(filePath string, target string, results []scan.TargetResult, duration time.Duration) error {
	report := XMLReport{
		Scanner:  "tcpcat",
		Version:  "5.0",
		Target:   target,
		Duration: duration.Round(time.Millisecond).String(),
		Host: XMLHost{
			Address: target,
		},
	}

	for _, r := range results {
		report.Host.Ports = append(report.Host.Ports, XMLPort{
			PortID:   r.Port,
			Protocol: "tcp",
			State:    XMLState{State: strings.ToLower(r.State)},
			Service:  XMLService{Name: r.Service, Banner: r.Banner},
		})
	}

	data, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("erreur de sérialisation XML: %w", err)
	}

	content := append([]byte(xml.Header), data...)
	return os.WriteFile(filePath, content, 0644)
}