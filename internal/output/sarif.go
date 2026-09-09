package output

import (
	"encoding/json"
	"fmt"
	"os"

	"tcpcat/internal/scan"
)

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string `json:"id"`
	ShortDescription string `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func ExportSARIF(filePath string, results []scan.TargetResult) error {
	run := sarifRun{Tool: sarifTool{Driver: sarifDriver{Name: "tcpcat"}}}
	rules := make(map[string]string)
	for _, result := range results {
		if result.State != scan.StateOpen {
			continue
		}
		location := []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: fmt.Sprintf("tcp://%s:%d", result.IP, result.Port)}}}}
		if len(result.Vulnerabilities) == 0 {
			ruleID := fmt.Sprintf("OPEN-PORT-%d", result.Port)
			rules[ruleID] = fmt.Sprintf("Open TCP port %d", result.Port)
			run.Results = append(run.Results, sarifResult{RuleID: ruleID, Level: "warning", Message: sarifMessage{Text: fmt.Sprintf("Open TCP port %d on %s", result.Port, result.IP)}, Locations: location})
			continue
		}
		for _, vulnerability := range result.Vulnerabilities {
			rules[vulnerability.ID] = vulnerability.Title
			level := "warning"
			if vulnerability.CVSS >= 7 {
				level = "error"
			}
			run.Results = append(run.Results, sarifResult{RuleID: vulnerability.ID, Level: level, Message: sarifMessage{Text: fmt.Sprintf("%s (CVSS %.1f) on %s:%d", vulnerability.Title, vulnerability.CVSS, result.IP, result.Port)}, Locations: location})
		}
	}
	for id, description := range rules {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{ID: id, ShortDescription: description})
	}
	report := sarifReport{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{run}}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize SARIF: %w", err)
	}
	return os.WriteFile(filePath, data, 0600)
}
