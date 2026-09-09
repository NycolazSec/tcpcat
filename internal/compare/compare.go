package compare

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"tcpcat/internal/scan"
)

type baselineReport struct {
	Target  string              `json:"target"`
	Results []scan.TargetResult `json:"results"`
}

type Report struct {
	ComparedAt         time.Time             `json:"compared_at"`
	NewOpenPorts       []PortChange          `json:"new_open_ports"`
	ServiceChanges     []ServiceChange       `json:"service_changes"`
	NewVulnerabilities []VulnerabilityChange `json:"new_vulnerabilities"`
}

type PortChange struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type ServiceChange struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	OldService string `json:"old_service"`
	OldVersion string `json:"old_version"`
	NewService string `json:"new_service"`
	NewVersion string `json:"new_version"`
}

type VulnerabilityChange struct {
	IP               string `json:"ip"`
	Port             int    `json:"port"`
	NewVulnerability string `json:"new_vulnerability"`
}

func LoadBaseline(filePath string) ([]scan.TargetResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var report baselineReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	return report.Results, nil
}

func Compare(current, baseline []scan.TargetResult) Report {
	baselineByAddress := make(map[string]scan.TargetResult, len(baseline))
	for _, result := range baseline {
		baselineByAddress[addressKey(result)] = result
	}

	report := Report{ComparedAt: time.Now().UTC()}
	for _, result := range current {
		previous, found := baselineByAddress[addressKey(result)]
		if result.State == scan.StateOpen && (!found || previous.State != scan.StateOpen) {
			report.NewOpenPorts = append(report.NewOpenPorts, PortChange{IP: result.IP, Port: result.Port})
		}
		if found && previous.State == scan.StateOpen && result.State == scan.StateOpen && (previous.Service != result.Service || previous.Version != result.Version) {
			report.ServiceChanges = append(report.ServiceChanges, ServiceChange{IP: result.IP, Port: result.Port, OldService: previous.Service, OldVersion: previous.Version, NewService: result.Service, NewVersion: result.Version})
		}
		oldVulnerabilities := make(map[string]struct{}, len(previous.Vulnerabilities))
		for _, vulnerability := range previous.Vulnerabilities {
			oldVulnerabilities[vulnerability.ID] = struct{}{}
		}
		for _, vulnerability := range result.Vulnerabilities {
			if _, existed := oldVulnerabilities[vulnerability.ID]; !existed {
				report.NewVulnerabilities = append(report.NewVulnerabilities, VulnerabilityChange{IP: result.IP, Port: result.Port, NewVulnerability: vulnerability.ID})
			}
		}
	}
	return report
}

func WriteReport(filePath string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize comparison report: %w", err)
	}
	return os.WriteFile(filePath, data, 0600)
}

func addressKey(result scan.TargetResult) string {
	return fmt.Sprintf("%s:%d", result.IP, result.Port)
}
