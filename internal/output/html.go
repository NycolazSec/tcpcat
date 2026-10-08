package output

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/NycolazSec/tcpcat/internal/scan"
	"github.com/NycolazSec/tcpcat/internal/vuln"
)

// ExportHTML writes a self-contained, shareable HTML report: one page, inline
// CSS, light/dark aware, no external assets. It lists open ports per host with
// service/version/OS/latency and, under each, the correlated CVEs with their
// CVSS, severity, and (when --exploit-intel ran) KEV/EPSS signals. All host-
// supplied text (banners, CVE titles, service names) is rendered through
// html/template, so a hostile banner cannot inject markup into the report.
func ExportHTML(filePath string, target string, results []scan.TargetResult, duration time.Duration) error {
	report := buildHTMLReport(target, results, duration)

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"sevClass": func(s string) string { return "sev-" + strings.ToLower(s) },
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("html: parse template: %w", err)
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()

	if err := tmpl.Execute(file, report); err != nil {
		return fmt.Errorf("html: render report: %w", err)
	}
	return nil
}

type htmlReport struct {
	Target    string
	Generated string
	Duration  string
	HostCount int
	OpenCount int
	CVECount  int
	SevCounts []htmlSevCount
	Hosts     []htmlHost
}

type htmlSevCount struct {
	Severity string
	Class    string
	Count    int
}

type htmlHost struct {
	IP        string
	OpenPorts int
	Ports     []htmlPort
}

type htmlPort struct {
	Port      string
	Service   string
	Version   string
	OS        string
	LatencyMs string
	Vulns     []htmlVuln
}

type htmlVuln struct {
	ID            string
	CVSS          string
	Severity      string
	KEV           bool
	EPSS          string
	Title         string
	NotApplicable bool
}

// severityRank orders the summary tiles most-severe first; anything unknown
// sorts last.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func buildHTMLReport(target string, results []scan.TargetResult, duration time.Duration) htmlReport {
	report := htmlReport{
		Target:    target,
		Generated: time.Now().Format("2006-01-02 15:04:05 MST"),
		Duration:  duration.Round(time.Millisecond).String(),
	}

	sevCounts := map[string]int{}

	for _, host := range groupByIP(target, results) {
		h := htmlHost{IP: host.IP}
		for _, r := range host.Results {
			if r.State != scan.StateOpen {
				continue
			}
			h.OpenPorts++
			report.OpenCount++

			svc := r.Service
			if svc == "" {
				svc = "unknown"
			}
			p := htmlPort{
				Port:      fmt.Sprintf("%d/tcp", r.Port),
				Service:   svc,
				Version:   r.Version,
				OS:        r.OS,
				LatencyMs: fmt.Sprintf("%.1f ms", r.LatencyMs),
			}
			for _, v := range r.Vulnerabilities {
				report.CVECount++
				sev := v.Severity
				if sev == "" {
					sev = vuln.SeverityForCVSS(v.CVSS)
				}
				notApplicable := v.Applicability != ""
				if !notApplicable {
					sevCounts[strings.ToLower(sev)]++
				}
				epss := ""
				if v.EPSS > 0 {
					epss = fmt.Sprintf("%.1f%%", v.EPSS*100)
				}
				p.Vulns = append(p.Vulns, htmlVuln{
					ID:            v.ID,
					CVSS:          fmt.Sprintf("%.1f", v.CVSS),
					Severity:      sev,
					KEV:           v.KnownExploited,
					EPSS:          epss,
					Title:         v.Title,
					NotApplicable: notApplicable,
				})
			}
			h.Ports = append(h.Ports, p)
		}
		if h.OpenPorts > 0 {
			report.HostCount++
			report.Hosts = append(report.Hosts, h)
		}
	}

	for sev, count := range sevCounts {
		report.SevCounts = append(report.SevCounts, htmlSevCount{
			Severity: sev,
			Class:    "sev-" + sev,
			Count:    count,
		})
	}
	sort.Slice(report.SevCounts, func(i, j int) bool {
		return severityRank(report.SevCounts[i].Severity) < severityRank(report.SevCounts[j].Severity)
	})

	return report
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tcpcat report — {{.Target}}</title>
<style>
  :root {
    --bg: #f6f7f9; --card: #ffffff; --fg: #1b1f24; --muted: #5b6672;
    --border: #e3e6ea; --accent: #2d6cdf;
    --critical: #b4232a; --high: #d9534f; --medium: #d98b1f; --low: #3a8a4f; --info: #6b7480;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #0f1216; --card: #171b21; --fg: #e6e9ed; --muted: #9aa4b0;
      --border: #272d35; --accent: #5b8cf0;
      --critical: #ff5a60; --high: #ff7b76; --medium: #f0ad4e; --low: #5cc274; --info: #9aa4b0;
    }
  }
  :root[data-theme="dark"] {
    --bg: #0f1216; --card: #171b21; --fg: #e6e9ed; --muted: #9aa4b0;
    --border: #272d35; --accent: #5b8cf0;
    --critical: #ff5a60; --high: #ff7b76; --medium: #f0ad4e; --low: #5cc274; --info: #9aa4b0;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg);
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .wrap { max-width: 960px; margin: 0 auto; padding: 32px 16px 64px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  h2 { font-size: 17px; margin: 32px 0 12px; }
  .meta { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
  .meta code { background: var(--card); border: 1px solid var(--border); border-radius: 4px; padding: 1px 6px; }
  .cards { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 14px 18px; min-width: 110px; flex: 1; }
  .card .n { font-size: 24px; font-weight: 650; }
  .card .l { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  table { width: 100%; border-collapse: collapse; background: var(--card);
    border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 8px; }
  th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 600; }
  tr:last-child td { border-bottom: none; }
  .host { font-size: 15px; font-weight: 650; margin: 28px 0 10px; }
  .host code { color: var(--accent); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
  .vulns { margin: 6px 0 2px; }
  .badge { display: inline-block; font-size: 11px; font-weight: 600; padding: 1px 7px; border-radius: 999px;
    color: #fff; white-space: nowrap; }
  .sev-critical { background: var(--critical); } .sev-high { background: var(--high); }
  .sev-medium { background: var(--medium); } .sev-low { background: var(--low); }
  .sev-info, .sev- { background: var(--info); }
  .kev { background: var(--critical); }
  .epss { background: transparent; color: var(--muted); border: 1px solid var(--border); }
  .dim { color: var(--muted); }
  .na { opacity: .55; }
  .empty { color: var(--muted); padding: 16px 0; }
  footer { margin-top: 48px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); padding-top: 16px; }
  footer a { color: var(--accent); }
</style>
</head>
<body>
<div class="wrap">
  <h1>tcpcat scan report</h1>
  <div class="meta">
    Target <code>{{.Target}}</code> · generated {{.Generated}} · scan duration {{.Duration}}
  </div>

  <div class="cards">
    <div class="card"><div class="n">{{.HostCount}}</div><div class="l">Hosts</div></div>
    <div class="card"><div class="n">{{.OpenCount}}</div><div class="l">Open ports</div></div>
    <div class="card"><div class="n">{{.CVECount}}</div><div class="l">CVE matches</div></div>
    {{range .SevCounts}}<div class="card"><div class="n"><span class="badge {{.Class}}">{{.Count}}</span></div><div class="l">{{.Severity}}</div></div>{{end}}
  </div>

  {{if .Hosts}}
  {{range .Hosts}}
  <div class="host">Host <code>{{.IP}}</code> <span class="dim">· {{.OpenPorts}} open port(s)</span></div>
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>OS</th><th>Latency</th></tr></thead>
    <tbody>
      {{range .Ports}}
      <tr>
        <td class="mono">{{.Port}}</td>
        <td>{{.Service}}</td>
        <td class="dim">{{if .Version}}{{.Version}}{{else}}—{{end}}</td>
        <td class="dim">{{if .OS}}{{.OS}}{{else}}—{{end}}</td>
        <td class="dim mono">{{.LatencyMs}}</td>
      </tr>
      {{if .Vulns}}
      <tr><td colspan="5">
        <table class="vulns">
          <thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Exploitation</th><th>Title</th></tr></thead>
          <tbody>
          {{range .Vulns}}
            <tr{{if .NotApplicable}} class="na"{{end}}>
              <td class="mono">{{.ID}}</td>
              <td class="mono">{{.CVSS}}</td>
              <td><span class="badge {{sevClass .Severity}}">{{.Severity}}</span></td>
              <td>
                {{if .KEV}}<span class="badge kev">KEV</span> {{end}}
                {{if .EPSS}}<span class="badge epss">EPSS {{.EPSS}}</span>{{end}}
                {{if not .KEV}}{{if not .EPSS}}<span class="dim">—</span>{{end}}{{end}}
              </td>
              <td class="dim">{{.Title}}{{if .NotApplicable}} <span class="dim">(not applicable)</span>{{end}}</td>
            </tr>
          {{end}}
          </tbody>
        </table>
      </td></tr>
      {{end}}
      {{end}}
    </tbody>
  </table>
  {{end}}
  {{else}}
  <p class="empty">No open ports were found.</p>
  {{end}}

  <footer>
    Generated by <a href="https://github.com/NycolazSec/tcpcat">tcpcat</a>.
    Version/banner-based CVE matches are correlation leads, not confirmed exploitability.
    For authorized security assessment only.
  </footer>
</div>
</body>
</html>
`
