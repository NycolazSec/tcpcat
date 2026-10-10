package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	StatusPass = "pass"
	StatusFail = "fail"
)

// Report is the outcome of one `policy check` run from one vantage.
type Report struct {
	Policy    string        `json:"policy"`
	Vantage   string        `json:"vantage"`
	CheckedAt time.Time     `json:"checked_at"`
	Status    string        `json:"status"`
	Checks    []CheckResult `json:"checks"`
}

type CheckResult struct {
	Rule       string      `json:"rule"`
	From       string      `json:"from"`
	To         string      `json:"to"`
	Targets    int         `json:"targets"`
	Ports      int         `json:"ports"`
	Status     string      `json:"status"`
	Open       []Endpoint  `json:"open"`
	Violations []Violation `json:"violations"`
}

// NewCheckResult evaluates a check against the endpoints found open.
func NewCheckResult(c Check, open []Endpoint) CheckResult {
	sort.Slice(open, func(i, j int) bool {
		if open[i].IP != open[j].IP {
			return open[i].IP < open[j].IP
		}
		return open[i].Port < open[j].Port
	})
	violations := c.Evaluate(open)
	status := StatusPass
	if len(violations) > 0 {
		status = StatusFail
	}
	if open == nil {
		open = []Endpoint{}
	}
	if violations == nil {
		violations = []Violation{}
	}
	return CheckResult{
		Rule: c.Rule.Name, From: c.Rule.From, To: c.Rule.To,
		Targets: len(c.Targets), Ports: len(c.Ports),
		Status: status, Open: open, Violations: violations,
	}
}

// Finalize sets the overall status: fail if any check failed.
func (r *Report) Finalize() {
	r.Status = StatusPass
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			r.Status = StatusFail
			return
		}
	}
}

func (r Report) WriteJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize policy report: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

func LoadReport(path string) (Report, error) {
	var r Report
	data, err := os.ReadFile(path)
	if err != nil {
		return r, fmt.Errorf("read report: %w", err)
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, fmt.Errorf("parse report %s: %w", path, err)
	}
	return r, nil
}

// WriteSARIF exports violations as SARIF 2.1.0, one rule per policy rule,
// so a CI pipeline (e.g. GitHub code scanning) can surface them.
func (r Report) WriteSARIF(path string) error {
	type message struct {
		Text string `json:"text"`
	}
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   message    `json:"message"`
		Locations []location `json:"locations"`
	}
	type rule struct {
		ID               string  `json:"id"`
		ShortDescription message `json:"shortDescription"`
	}

	rules := []rule{}
	results := []result{}
	for _, c := range r.Checks {
		id := "POLICY-" + slug(c.Rule)
		rules = append(rules, rule{ID: id, ShortDescription: message{Text: fmt.Sprintf("Segmentation rule %q (%s -> %s)", c.Rule, c.From, c.To)}})
		for _, v := range c.Violations {
			var loc location
			loc.PhysicalLocation.ArtifactLocation.URI = fmt.Sprintf("tcp://%s", joinHostPort(v.IP, v.Port))
			text := fmt.Sprintf("%s:%d is reachable from %s but not allowed by rule %q", v.IP, v.Port, c.From, c.Rule)
			if v.Kind == ViolationRequiredClosed {
				text = fmt.Sprintf("%s:%d must be reachable from %s (rule %q) but is not", v.IP, v.Port, c.From, c.Rule)
			}
			results = append(results, result{RuleID: id, Level: "error", Message: message{Text: text}, Locations: []location{loc}})
		}
	}
	doc := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []interface{}{map[string]interface{}{
			"tool":       map[string]interface{}{"driver": map[string]interface{}{"name": "tcpcat-policy", "rules": rules}},
			"results":    results,
			"properties": map[string]interface{}{"policy": r.Policy, "vantage": r.Vantage},
		}},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize SARIF: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// PrintMatrix renders reports from several vantages as one from/to table.
func PrintMatrix(w io.Writer, reports []Report) {
	_, _ = fmt.Fprintf(w, "%-18s %-22s %-6s %s\n", "FROM", "TO", "STATUS", "DETAIL")
	for _, rep := range reports {
		for _, c := range rep.Checks {
			detail := fmt.Sprintf("%d reachable, as allowed", len(c.Open))
			if c.Status == StatusFail {
				var parts []string
				for _, v := range c.Violations {
					mark := "OPEN"
					if v.Kind == ViolationRequiredClosed {
						mark = "MISSING"
					}
					parts = append(parts, fmt.Sprintf("%s %s", mark, joinHostPort(v.IP, v.Port)))
				}
				detail = strings.Join(parts, ", ")
			}
			_, _ = fmt.Fprintf(w, "%-18s %-22s %-6s %s\n", c.From, c.To, strings.ToUpper(c.Status), detail)
		}
	}
}

func joinHostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}
